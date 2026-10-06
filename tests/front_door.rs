//! The front door: the public URL's own path signs a user in to My Account in
//! the tenant owning their UPN's suffix.

mod common;

use common::*;

/// What a browser does with a 307: post the same form to the new place.
async fn follow(b: &Browser, sent: &Page, upn: &str, password: &str) -> Page {
    let posted = b.login(sent, upn, password).await;
    assert_eq!(posted.status, 307, "{}", posted.body);
    let to = posted.location.clone().expect("a location");
    let form = [
        ("csrf", sent.field("csrf").unwrap()),
        ("request", String::new()),
        ("op", "login".to_string()),
        ("upn", upn.to_string()),
        ("password", password.to_string()),
    ];
    let form: Vec<(&str, &str)> = form.iter().map(|(k, v)| (*k, v.as_str())).collect();
    b.post_form(&to, &form).await
}

#[tokio::test]
async fn the_front_door_signs_in_to_the_upns_own_tenant() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    for path in ["", "/"] {
        let b = Browser::new();
        let door = b.get(&s.url(path)).await;
        assert_eq!(door.status, 200, "{path:?}: {}", door.body);
        assert_eq!(door.form_action(), s.url("/"));
        let posted = b.login(&door, &f.upn, &f.password).await;
        assert_eq!(
            posted.location.as_deref(),
            Some(s.url(&format!("/{}/myaccount", f.tenant.id)).as_str())
        );
        let page = follow(&b, &door, &f.upn, &f.password).await;
        assert!(page.body.contains("<h1>My account</h1>"), "{}", page.body);
        assert!(page.body.contains(&f.upn), "{}", page.body);
    }
}

#[tokio::test]
async fn a_wrong_password_is_refused_by_my_account() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await;
    let b = Browser::new();
    let door = b.get(&s.url("/")).await;
    let page = follow(&b, &door, &f.upn, "not-the-password").await;
    assert!(page.body.contains("AADSTS50126"), "{}", page.body);
    assert!(!page.body.contains("<h1>My account</h1>"), "{}", page.body);
}

#[tokio::test]
async fn an_unknown_suffix_stays_at_the_door() {
    let s = TestServer::start().await;
    let _f = user_fixture(&s).await;
    let b = Browser::new();
    let door = b.get(&s.url("/")).await;
    for upn in ["alice@nowhere.example", "no-suffix"] {
        let page = b.login(&door, upn, "whatever").await;
        assert_eq!(page.status, 401, "{upn}: {}", page.body);
        assert!(page.location.is_none());
        assert!(page.body.contains("AADSTS50126"), "{}", page.body);
    }
}

#[tokio::test]
async fn the_console_answers_with_a_trailing_slash() {
    let s = TestServer::start().await;
    let b = Browser::new();
    let page = b.get(&s.url("/admin/")).await;
    assert_eq!(page.status, 308);
    assert_eq!(page.location.as_deref(), Some(s.url("/admin").as_str()));
}
