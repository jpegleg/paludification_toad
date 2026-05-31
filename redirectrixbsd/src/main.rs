use pledge::pledge_promises;
use unveil::unveil;
use actix_files::Files;
use actix_web::{
    body::EitherBody,
    dev::{Service, ServiceRequest, ServiceResponse, Transform},
    App, Error, HttpResponse, HttpServer,
};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use std::task::{Context, Poll};

struct RedirectToHttps;

impl<S, B> Transform<S, ServiceRequest> for RedirectToHttps
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type InitError = ();
    type Transform = RedirectToHttpsMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RedirectToHttpsMiddleware { service })
    }
}

struct RedirectToHttpsMiddleware<S> {
    service: S,
}

impl<S, B> Service<ServiceRequest> for RedirectToHttpsMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_string();
        if path.starts_with("/.well-known") {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        let host = req.connection_info().host().to_string();
        let uri = req.uri().to_string();
        let location = format!("https://{}{}", host, uri);

        let response = HttpResponse::MovedPermanently()
            .append_header(("Location", location))
            .finish()
            .map_into_right_body();

        Box::pin(async move { Ok(req.into_response(response)) })
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    pledge_promises![Stdio Inet Rpath Getpw Unveil].unwrap();
    let acmepath = "/.well-known";
    let acmepath2 = "http-01-webroot/.well-known";
    unveil(acmepath, "r")
        .or_else(unveil::Error::ignore_platform)
        .unwrap();
    unveil(acmepath2, "r")
        .or_else(unveil::Error::ignore_platform)
        .unwrap();

    HttpServer::new(|| {
        App::new()
            .wrap(RedirectToHttps)
            .service(Files::new("/.well-known", "http-01-webroot/.well-known"))
    })
    .bind("0.0.0.0:80")?
    .run()
    .await
}
