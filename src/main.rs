use std::sync::Arc;

use dashmap::DashMap;
use poise::serenity_prelude as serenity;
use reqwest::Client;
use tokio::sync::mpsc;
use tokio::task;

mod engine;
mod vm;

const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;
const PLATOBOOST_PROJECT: &str = "3035";
const PLATOBOOST_SECRET: &str = "e787153b-65f0-4a2a-b209-7bf2ddf2b8bc";

#[derive(Clone, Debug)]
struct Session {
    file_bytes: Option<Vec<u8>>,
    option: Option<ProtectionLevel>,
    verified: bool,
}

impl Session {
    fn new() -> Self {
        Self {
            file_bytes: None,
            option: None,
            verified: false,
        }
    }

    fn reset_for_new_request(&mut self) {
        self.verified = false;
        self.option = None;
        self.file_bytes = None;
    }
}

#[derive(Clone, Copy, Debug, serde::Serialize, serde::Deserialize)]
pub enum ProtectionLevel {
    Default,
    Heavy,
    Light,
}

type Sessions = Arc<DashMap<u64, Session>>;

type ProcessingQueueSender = mpsc::Sender<WorkItem>;

type ProcessingQueueReceiver = mpsc::Receiver<WorkItem>;

#[derive(Clone)]
struct BotData {
    sessions: Sessions,
    queue: ProcessingQueueSender,
    http_client: Client,
    discord_http: Arc<serenity::Http>,
}

#[derive(Clone)]
struct WorkItem {
    user_id: u64,
    channel_id: serenity::ChannelId,
    option: ProtectionLevel,
    file_bytes: Vec<u8>,
}

#[derive(serde::Deserialize)]
struct PlatoboostResponse {
    valid: bool,
}

fn platoboost_link(user_id: u64) -> String {
    format!(
        "https://gateway.platoboost.com/a/{}?id={}",
        PLATOBOOST_PROJECT, user_id
    )
}

async fn verify_key(client: &Client, key: &str) -> anyhow::Result<bool> {
    let url = format!(
        "https://api.platoboost.com/v1/public/verify?public_key={}&key={}",
        PLATOBOOST_PROJECT, key
    );
    let resp = client.get(url).send().await?.error_for_status()?;
    let parsed: PlatoboostResponse = resp.json().await?;
    Ok(parsed.valid)
}

/// Background worker consuming the queue and dispatching encrypted payloads.
async fn start_consumer(mut rx: ProcessingQueueReceiver, bot: BotData) {
    while let Some(item) = rx.recv().await {
        let bot_clone = bot.clone();
        task::spawn(async move {
            match task::spawn_blocking(move || engine::protect_script(item.file_bytes, item.option))
                .await
            {
                Ok(Ok(protected)) => {
                    let payload = vm::assemble_loader(&protected);
                    let content = format!(
                        "✅ Encryption complete (option: {:?}). Key: {}\n````lua\n{}\n````",
                        item.option, protected.opaque_key, payload
                    );
                    let _ = item
                        .channel_id
                        .send_message(bot_clone.discord_http.as_ref(), |m| m.content(content))
                        .await;
                }
                Ok(Err(e)) => {
                    let _ = item
                        .channel_id
                        .send_message(bot_clone.discord_http.as_ref(), |m| {
                            m.content(format!("❌ Failed to encrypt: {}", e))
                        })
                        .await;
                }
                Err(join_err) => {
                    let _ = item
                        .channel_id
                        .send_message(bot_clone.discord_http.as_ref(), |m| {
                            m.content(format!("❌ Worker join error: {}", join_err))
                        })
                        .await;
                }
            }
        });
    }
}

/// Slash command: /help
#[poise::command(slash_command)]
async fn help(ctx: poise::Context<'_, BotData, anyhow::Error>) -> Result<(), anyhow::Error> {
    let response = "Upload a Lua/Luau file (<5MB), pick an option (Default/Heavy/Light), then retrieve the Platoboost key from the link we send. Provide it with /key <KEY> to start encryption.";
    ctx.say(response).await?;
    Ok(())
}

/// Slash command: /upload
#[poise::command(slash_command)]
async fn upload(
    ctx: poise::Context<'_, BotData, anyhow::Error>,
    #[description = "Lua/Luau script attachment"] attachment: serenity::Attachment,
) -> Result<(), anyhow::Error> {
    if attachment.size > MAX_FILE_SIZE as i32 {
        ctx.say("File too large. Please keep under 5MB.").await?;
        return Ok(());
    }

    let http_client = &ctx.data().http_client;
    let bytes = http_client
        .get(attachment.url.clone())
        .send()
        .await?
        .bytes()
        .await?;

    let user_id = ctx.author().id.0;
    let mut entry = ctx
        .data()
        .sessions
        .entry(user_id)
        .or_insert_with(Session::new);
    entry.reset_for_new_request();
    entry.file_bytes = Some(bytes.to_vec());

    ctx.say(
        "File received. Choose encryption option: Default, Heavy, or Light using /option <level>.",
    )
    .await?;
    Ok(())
}

/// Slash command: /option
#[poise::command(slash_command)]
async fn option(
    ctx: poise::Context<'_, BotData, anyhow::Error>,
    #[description = "Protection level"] level: String,
) -> Result<(), anyhow::Error> {
    let level_norm = level.to_lowercase();
    let option = match level_norm.as_str() {
        "default" => ProtectionLevel::Default,
        "heavy" => ProtectionLevel::Heavy,
        "light" => ProtectionLevel::Light,
        _ => {
            ctx.say("Unknown option. Use Default, Heavy, or Light.")
                .await?;
            return Ok(());
        }
    };

    let user_id = ctx.author().id.0;
    let mut entry = ctx
        .data()
        .sessions
        .entry(user_id)
        .or_insert_with(Session::new);
    entry.option = Some(option);
    entry.verified = false;

    let link = platoboost_link(user_id);
    ctx.say(format!(
        "Option set to {:?}. Retrieve your key here: {}. Then run /key <KEY>.",
        option, link
    ))
    .await?;
    Ok(())
}

/// Slash command: /key
#[poise::command(slash_command)]
async fn key(
    ctx: poise::Context<'_, BotData, anyhow::Error>,
    #[description = "Platoboost key"] key: String,
) -> Result<(), anyhow::Error> {
    let user_id = ctx.author().id.0;
    let Some(mut session) = ctx.data().sessions.get_mut(&user_id) else {
        ctx.say("No active session. Upload a file first with /upload.")
            .await?;
        return Ok(());
    };

    let valid = verify_key(&ctx.data().http_client, &key).await?;
    if !valid {
        ctx.say("Invalid key. Please try again from the Platoboost link.")
            .await?;
        session.verified = false;
        return Ok(());
    }

    session.verified = true;

    if session.file_bytes.is_none() || session.option.is_none() {
        ctx.say("Missing file or option. Please upload and select option before submitting key.")
            .await?;
        session.verified = false;
        return Ok(());
    }

    let work = WorkItem {
        user_id,
        channel_id: ctx.channel_id(),
        option: session.option.unwrap(),
        file_bytes: session.file_bytes.clone().unwrap(),
    };

    ctx.data().queue.send(work).await.ok();
    ctx.say("Key verified. Job queued for encryption. You'll receive output shortly.")
        .await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt::init();
    let sessions: Sessions = Arc::new(DashMap::new());
    let (tx, rx) = mpsc::channel(64);
    let http_client = Client::builder().user_agent("drk-v3-bot").build()?;

    let framework = poise::Framework::builder()
        .options(poise::FrameworkOptions {
            commands: vec![help(), upload(), option(), key()],
            ..Default::default()
        })
        .token(std::env::var("DISCORD_TOKEN")?)
        .intents(
            serenity::GatewayIntents::non_privileged() | serenity::GatewayIntents::MESSAGE_CONTENT,
        )
        .setup(move |ctx, _ready, framework| {
            let data = BotData {
                sessions: sessions.clone(),
                queue: tx.clone(),
                http_client: http_client.clone(),
                discord_http: framework.client().cache_and_http.http.clone(),
            };

            let consumer_data = data.clone();
            tokio::spawn(start_consumer(rx, consumer_data));

            Box::pin(async move {
                poise::builtins::register_globally(ctx, &framework.options().commands).await?;
                Ok(data)
            })
        })
        .build();

    framework.run().await?;
    Ok(())
}
