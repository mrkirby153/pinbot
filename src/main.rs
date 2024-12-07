use std::env;

use anyhow::Result;
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use tokio::net::TcpListener;
use tracing::{debug, info, warn};
use twilight_model::{
    application::interaction::{Interaction, InteractionType},
    http::interaction::{InteractionResponse, InteractionResponseType},
};
use verifier::Verifier;

mod verifier;

#[derive(Clone)]
struct AppState {
    verifier: Verifier,
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

    let state = AppState { verifier };

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

    debug!("Body: {:?}", body);

    let interaction =
        serde_json::from_str::<Interaction>(&body).map_err(|_| StatusCode::BAD_REQUEST)?;

    let resp = match interaction.kind {
        InteractionType::Ping => InteractionResponse {
            kind: InteractionResponseType::Pong,
            data: None,
        },
        _ => {
            return Err(StatusCode::BAD_REQUEST);
        }
    };
    debug!("Response: {:?}", resp);
    Ok(Json(resp))
}
