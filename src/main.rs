use std::borrow::Borrow;
use std::collections::HashMap;
use std::sync::Mutex;
use std::thread;
use std::time::Duration;

use actix_web::web::{Bytes, Data};
use actix_web::{web, App, HttpRequest, HttpServer};
use crypto::hmac::Hmac;
use crypto::mac::Mac;

use crypto::sha2::Sha256;
use crypto::util::fixed_time_eq;

use chrono::{DateTime, Utc};
use ini::Ini;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderValue};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};

mod error;
use crate::error::Error;
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    configuration: String,
}

pub struct SharedData {
    pending_events: Mutex<Vec<(DateTime<Utc>, Event)>>,
    configuration: Mutex<Configuration>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Event {
    event: String,
    created_at: String,
    object: Object,
}

#[derive(Debug, Serialize, Deserialize)]
struct Object {
    id: String,
    username: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct Account {
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AdminAccount {
    confirmed: bool,
    approved: bool,
}

#[derive(Default, Parser, Debug, Clone)]
struct Configuration {
    message_pattern: String,
    message_max_len: usize,
    user_max_len: usize,
    api_url: String,
    local_domain: String,
    webhook_key: String,
    api_token: String,
    address: String,
    port: u16,
}

impl Configuration {
    fn read_from_file(&mut self, filename: String) {
        let conf = Ini::load_from_file(filename.clone())
            .unwrap_or_else(|_| panic!("File {} not found.", filename));
        let network = conf
            .section(Some("Network"))
            .expect("[Network] section not found.");
        let instance = conf
            .section(Some("Instance"))
            .expect("[Instance] section not found.");
        let secrets = conf
            .section(Some("Secrets"))
            .expect("[Secrets] section not found.");
        let message = conf
            .section(Some("Message"))
            .expect("[Message] section not found.");

        self.message_pattern = message
            .get("message_pattern")
            .expect("`message_pattern` not found.")
            .to_string();

        self.message_max_len = message
            .get("message_max_len")
            .expect("`message_max_len` not found.")
            .parse::<usize>()
            .unwrap();
        self.user_max_len = message
            .get("user_max_len")
            .expect("`user_max_len` not found.")
            .parse::<usize>()
            .unwrap();
        self.api_url = instance
            .get("web_domain")
            .expect("`api_url` not found.")
            .to_string();
        self.local_domain = instance
            .get("local_domain")
            .expect("`local_domain` not found.")
            .to_string();
        self.webhook_key = secrets
            .get("webhook_key")
            .expect("`webhook_token` not found.")
            .to_string();
        self.api_token = secrets
            .get("write_token")
            .expect("`api_token` not found.")
            .to_string();
        self.address = network
            .get("address")
            .expect("`address` not found.")
            .to_string();
        self.port = network
            .get("port")
            .expect("`port` not found.")
            .parse::<u16>()
            .unwrap();
    }

    fn check(&self) -> Result<(), Error> {
        let test_message = self
            .message_pattern
            .replace("USERNAME", &"U".repeat(self.user_max_len));

        /* See https://github.com/mastodon/mastodon/blob/06b68490d1957d680adc0c0c4ed2c84641de2056/app/javascript/mastodon/features/compose/util/counter.js */
        let username_re =
            Regex::new(r"(^|[^/\w])@(([a-zA-Z0-9_]+)@[a-zA-Z0-9\.\-]+[a-zA-Z0-9]+)").unwrap();
        /* Ugly regex because I don't want to deal with twitter-text */
        let link_re = Regex::new(r"(https?://[a-zA-Z0-9\./?]+)").unwrap();
        let displayed_message = username_re.replace_all(&test_message, "$1@$3");
        let displayed_message = link_re.replace_all(&displayed_message, "xxxxxxxxxxxxxxxxxxxxxxx");

        if displayed_message.len() > self.message_max_len {
            return Err(Error::Configuration(format!(
                "The message template may overflows the message_max_len ({} > {}).",
                displayed_message.len(),
                self.message_max_len
            )));
        }
        Ok(())
    }
}

fn check_hash(local_key: &str, body: Bytes, signature: &str) -> bool {
    let mut hmac = Hmac::new(Sha256::new(), local_key.as_bytes());
    hmac.input(&body);
    let my_hash = hmac.result();
    let my_code = my_hash.code();
    let signature = hex::decode(signature).expect("Decoding failed");
    fixed_time_eq(&signature, my_code)
}

/* TODO: use a templating language ? */
fn make_status_str(message_pattern: &str, event: &Event) -> String {
    message_pattern.replace("USERNAME", &event.object.username)
}

async fn greet(
    body: Bytes,
    query: HttpRequest,
    shared_data: actix_web::web::Data<SharedData>,
) -> Result<String, Error> {
    let conf = &mut shared_data.configuration.lock().unwrap();
    let headers = query.headers();
    let header_signature = headers
        .get("x-hub-signature")
        .ok_or_else(|| Error::Webhook("Missing 'x-hub-signature' header.".to_string()))?;

    let signature = header_signature.to_str()?;

    let re = Regex::new(r"^sha256=(?P<hash>[a-fA-F0-9]{64})$").unwrap();
    let hash = re
        .captures(signature)
        .and_then(|cap| cap.name("hash").map(|hash| hash.as_str()))
        .ok_or_else(|| Error::Webhook("Wrong 'x-hub-signature' format.".to_string()))?;

    if check_hash(&conf.webhook_key, body.clone(), hash) {
        let event: Event = serde_json::from_slice(&body).unwrap();
        let mut pending_events = shared_data.borrow().pending_events.lock().unwrap();
        pending_events.push((chrono::offset::Utc::now(), event));
        return Ok("Successfully sent notification".to_string());
    }
    Err(Error::Webhook(
        "Wrong 'x-hub-signature' signature.".to_string(),
    ))
}

fn get_account_id(api_url: &str, username: &str) -> Option<String> {
    let client = reqwest::blocking::Client::new();
    let accounts = format!("{}{}", api_url, "api/v1/accounts/lookup");

    if let Ok(answer) = client.get(accounts).query(&[("acct", username)]).send() {
        if let Ok(text) = answer.text() {
            if let Ok(account) = serde_json::from_str::<Account>(&text) {
                return Some(account.id);
            }
        }
    }
    None
}

fn check_confirmed(api_url: &str, id: &str, headers: HeaderMap) -> bool {
    let client = reqwest::blocking::Client::new();
    let accounts = format!("{}{}{}", api_url, "api/v1/admin/accounts/", id);

    if let Ok(answer) = client.get(accounts).headers(headers).send() {
        if let Ok(text) = answer.text() {
            if let Ok(admin_account) = serde_json::from_str::<AdminAccount>(&text) {
                return admin_account.confirmed;
            } else {
                /* The token might not have the good authorizations */
                /* TODO */
            }
        }
    }
    false
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let args = Args::parse();

    /* TODO: Better error handling */
    let mut conf = Configuration::default();
    conf.read_from_file(args.configuration);
    conf.check()?;

    let shared_data = Data::new(SharedData {
        pending_events: Mutex::new(vec![]),
        configuration: Mutex::new(conf.clone()),
    });

    let data = shared_data.clone();
    let _ = thread::spawn(move || loop {
        let mut headers = HeaderMap::new();
        let bearer = format!("Bearer {}", conf.api_token);
        headers.insert("Authorization", HeaderValue::from_str(&bearer).unwrap());

        let mut mutex_guard = data.pending_events.lock().unwrap();
        let tuple = mutex_guard.pop();
        drop(mutex_guard);
        if let Some((timestamp, event)) = tuple {
            let mut reenqueue = true;
            if let Some(id) = get_account_id(&conf.api_url, &event.object.username) {
                if check_confirmed(&conf.api_url, &id, headers.clone()) {
                    let mut map = HashMap::new();
                    map.insert(
                        "status",
                        make_status_str(conf.message_pattern.as_str(), &event),
                    );
                    map.insert("visibility", "direct".to_string());

                    let client = reqwest::blocking::Client::new();
                    let statuses = format!("{}{}", conf.api_url, "api/v1/statuses");

                    let resp = client
                        .post(statuses)
                        .headers(headers)
                        .json(&map)
                        .send()
                        .unwrap();
                    match resp.status() {
                        StatusCode::OK => println!("success!"),
                        StatusCode::UNPROCESSABLE_ENTITY => {
                            println!("Request payload is probably too large!");
                        }
                        s => println!("Received response status: {:?}", s),
                    };
                    reenqueue = false;
                } else {
                    println!("Account is unconfirmed yet…");
                }
            } else {
                println!("Problem getting account id…");
            }
            if reenqueue {
                println!("Re-enqueue {:?} at the end…", event);
                let mut mutex_guard = data.pending_events.lock().unwrap();
                mutex_guard.push((timestamp, event));
                drop(mutex_guard);
            }
        }
        thread::sleep(Duration::from_secs(10));
    });

    HttpServer::new(move || {
        App::new()
            .app_data(shared_data.clone())
            .route("/", web::post().to(greet))
    })
    .bind((conf.address, conf.port))?
    .run()
    .await
}
