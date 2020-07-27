use delta_db::{calc_hash, Database, Hash, Options};
use futures::prelude::*;
use hyper::service::{make_service_fn, service_fn};
use hyper::{header, Body, Method, Request, Response, Server, StatusCode};
use std::sync::Arc;

type GenericError = Box<dyn std::error::Error + Send + Sync>;
type Result<T> = std::result::Result<T, GenericError>;

async fn handle_request(req: Request<Body>, db: Arc<Database>) -> Result<Response<Body>> {
    let (req, body) = req.into_parts();
    let uri = req.uri;
    let path = uri.path();

    // Get the blob name segment
    if !path.starts_with("/blobs/") {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body("Illegal requeust URL. Must begin with /blobs/".into())
            .unwrap());
    }
    let blob_name = &path["/blobs/".len()..];

    // Get the hash from string
    let blob_hash = if blob_name.is_empty() {
        None
    } else {
        match blob_name.parse::<Hash>() {
            Ok(v) => Some(v),
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body("Illegal requeust URL. Hash is not valid".into())
                    .unwrap())
            }
        }
    };

    // Get the link param from query
    let link_name = uri.query().and_then(|p| {
        url::form_urlencoded::parse(p.as_bytes())
            .find(|(k, _)| k == "link")
            .map(|(_, v)| v)
    });
    let link_hash = match link_name {
        None => None,
        Some(v) => match v.parse::<Hash>() {
            Ok(v) => Some(v),
            Err(_) => {
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body("Illegal requeust URL. Hash is not valid".into())
                    .unwrap())
            }
        },
    };

    match req.method {
        Method::GET => {
            let blob_hash = match blob_hash {
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body("Hash must be specified for GET".into())
                        .unwrap())
                }
                Some(v) => v,
            };
            let time = std::time::Instant::now();
            let blob = db.get(&blob_hash).await?;
            eprintln!("{:?}", time.elapsed());
            match blob {
                Some(blob) => {
                    return Ok(Response::builder()
                        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
                        .body(blob.into())
                        .unwrap())
                }
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body("".into())
                        .unwrap())
                }
            }
        }
        Method::PUT => {
            let entire_body = body
                .try_fold(Vec::new(), |mut data, chunk| async move {
                    data.extend_from_slice(&chunk);
                    Ok(data)
                })
                .await?;

            if let Some(v) = blob_hash {
                if v != calc_hash(&entire_body) {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body("Hash mismatch with body".into())
                        .unwrap());
                }
            }

            let hash = db.insert(&entire_body).await?;
            if let Some(v) = link_hash {
                db.link(&hash, &v).await?;
            }

            return Ok(Response::builder()
                .status(StatusCode::CREATED)
                .header(header::LOCATION, format!("/blobs/{}", hash))
                .body(Body::empty())
                .unwrap());
        }
        Method::PATCH => {
            let blob_hash = match blob_hash {
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body("Hash must be specified for PATCH".into())
                        .unwrap())
                }
                Some(v) => v,
            };

            let link_hash = match link_hash {
                None => {
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body("Hash must be specified for PATCH".into())
                        .unwrap())
                }
                Some(v) => v,
            };

            db.link(&blob_hash, &link_hash).await?;
            return Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Body::empty())
                .unwrap());
        }
        _ => {
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body("Unexpected request method".into())
                .unwrap());
        }
    }
}

pub async fn start_server(addr: std::net::SocketAddr, db: Arc<Database>) -> Result<()> {
    let new_service = make_service_fn(move |_| {
        let db = db.clone();
        async { Ok::<_, GenericError>(service_fn(move |req| handle_request(req, db.clone()))) }
    });

    let server = Server::bind(&addr).serve(new_service);

    println!("Listening on http://{}", addr);

    server.await?;

    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    let mut opts = getopts::Options::new();
    opts.optopt("h", "host", "address to listen on", "HOST");
    opts.optopt("p", "port", "port to listen on", "PORT");
    opts.reqopt("f", "database", "path to database", "PATH");

    let matches = opts.parse(&args[1..]).unwrap();
    let path = matches.opt_str("f").unwrap();
    let port = matches.opt_get("p").unwrap().unwrap_or(3000u16);
    let host = matches
        .opt_get("h")
        .unwrap()
        .unwrap_or("127.0.0.1".parse().unwrap());
    let addr = std::net::SocketAddr::new(host, port);

    let db = Arc::new(Database::open(path, &Options::default()).unwrap());
    start_server(addr, db.clone()).await.unwrap();
}
