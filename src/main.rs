use std::{env, sync::Arc};

use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};
use twilight_http::Client;
use twilight_model::{
    application::{
        command::{Command, CommandType},
        interaction::{Interaction, InteractionData, InteractionType},
    },
    channel::{message::MessageFlags, Channel},
    guild::Permissions,
    http::interaction::{InteractionResponse, InteractionResponseData, InteractionResponseType},
    id::{marker::GenericMarker, Id},
};
use twilight_util::builder::command::CommandBuilder;
use verifier::Verifier;

mod verifier;

#[derive(Clone)]
struct AppState {
    verifier: Verifier,
    client: Arc<Client>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    if dotenvy::dotenv().is_err() {
        warn!("No .env file found");
    } else {
        debug!("Loaded .env file");
    }

    let verifier = Verifier::new(
        env::var("INTERACTION_KEY")
            .expect("INTERACTION_KEY must be set")
            .as_str(),
    );
    let client = Arc::new(Client::new(
        env::var("BOT_TOKEN").expect("Bot token must be set"),
    ));

    let state = AppState { verifier, client };

    let current_user = state
        .client
        .current_user()
        .await
        .unwrap()
        .model()
        .await
        .unwrap();

    info!(
        "Logged in as {}#{}",
        current_user.name, current_user.discriminator
    );

    update_commands(state.client.clone())
        .await
        .expect("Could not update commands");

    let app = Router::new()
        .route("/_health", get(health))
        .route("/interaction_callback", post(interaction_callback))
        .with_state(state);

    let listener = TcpListener::bind("0.0.0.0:3000").await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> &'static str {
    "OK"
}

async fn update_commands(client: Arc<Client>) -> Result<()> {
    let application_id = {
        let response = client.current_user_application().await?;

        response.model().await?.id
    };

    let client = client.interaction(application_id);

    let guild_id = env::var("GUILD_ID");

    let commands = vec![
        CommandBuilder::new("ping", "Pings the bot", CommandType::ChatInput).build(),
        CommandBuilder::new("Pin/Unpin", "", CommandType::Message).build(),
    ];

    match guild_id {
        Ok(guild_id) => {
            info!("Registering commands for guild {}", guild_id);
            let guild_id = Id::new(guild_id.parse::<u64>().unwrap());

            client.set_guild_commands(guild_id, &commands).await?;
        }
        _ => {
            info!("Registering global commands");
            client.set_global_commands(&commands).await?;
        }
    }
    Ok(())
}

#[axum::debug_handler]
async fn interaction_callback(
    headers: HeaderMap,
    State(state): State<AppState>,
    body: String,
) -> Result<Json<InteractionResponse>, StatusCode> {
    debug!("Received interaction callback");

    let signature = headers
        .get("x-signature-ed25519")
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    let timestamp = headers
        .get("x-signature-timestamp")
        .ok_or(StatusCode::BAD_REQUEST)?
        .to_str()
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    debug!("Signature: {:?}", signature);
    debug!("Timestamp: {:?}", timestamp);

    if state
        .verifier
        .verify(signature, timestamp, body.as_bytes())
        .is_err()
    {
        debug!("Invalid signature");
        return Err(StatusCode::UNAUTHORIZED);
    }
    debug!("Signature is valid");

    let interaction =
        serde_json::from_str::<Interaction>(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let resp = match interaction.kind {
        InteractionType::Ping => InteractionResponse {
            kind: InteractionResponseType::Pong,
            data: None,
        },
        InteractionType::ApplicationCommand => {
            if let Some(
                twilight_model::application::interaction::InteractionData::ApplicationCommand(
                    command,
                ),
            ) = interaction.data
            {
                debug!("Processing command: {:?}", command.name);
                if command.name == "ping" {
                    InteractionResponse {
                        kind: InteractionResponseType::ChannelMessageWithSource,
                        data: Some(InteractionResponseData {
                            content: Some("Pong!".to_string()),
                            ..Default::default()
                        }),
                    }
                } else if command.name == "Pin/Unpin" {
                    match pin_unpin(
                        state.client.clone(),
                        interaction.channel.unwrap(),
                        command.target_id.unwrap(),
                    )
                    .await
                    {
                        Ok(resp) => InteractionResponse {
                            kind: InteractionResponseType::ChannelMessageWithSource,
                            data: Some(resp),
                        },
                        Err(e) => InteractionResponse {
                            kind: InteractionResponseType::ChannelMessageWithSource,
                            data: Some(InteractionResponseData {
                                content: Some(format!("Error: {:?}", e)),
                                flags: Some(MessageFlags::EPHEMERAL),
                                ..Default::default()
                            }),
                        },
                    }
                } else {
                    warn!("Unhandled command: {:?}", command.name);
                    InteractionResponse {
                        kind: InteractionResponseType::ChannelMessageWithSource,
                        data: Some(InteractionResponseData {
                            content: Some("Unhandled command".to_string()),
                            flags: Some(MessageFlags::EPHEMERAL),
                            ..Default::default()
                        }),
                    }
                }
            } else {
                warn!("Unhandled interaction type: {:?}", interaction.data);
                InteractionResponse {
                    kind: InteractionResponseType::ChannelMessageWithSource,
                    data: Some(InteractionResponseData {
                        content: Some("Unimplemented".to_string()),
                        flags: Some(MessageFlags::EPHEMERAL),
                        ..Default::default()
                    }),
                }
            }
        }
        _ => {
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    debug!("Response: {:?}", resp);
    Ok(Json(resp))
}

async fn pin_unpin(
    client: Arc<Client>,
    channel: Channel,
    message_id: Id<GenericMarker>,
) -> anyhow::Result<InteractionResponseData> {
    debug!(
        "Pinning message {:?} in channel {:?}",
        message_id, channel.id
    );

    let message = client
        .message(channel.id, message_id.cast())
        .await?
        .model()
        .await?;

    if message.pinned {
        debug!("Unpinning message");
        client.delete_pin(channel.id, message_id.cast()).await?;
        Ok(InteractionResponseData {
            content: Some(":pushpin: Message unpinned".to_string()),
            ..Default::default()
        })
    } else {
        debug!("Pinning message");
        client.create_pin(channel.id, message_id.cast()).await?;
        Ok(InteractionResponseData {
            content: Some(":pushpin: Message pinned".to_string()),
            ..Default::default()
        })
    }
}
