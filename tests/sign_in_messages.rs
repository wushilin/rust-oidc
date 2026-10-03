//! What a failed sign-in says. A name of another organisation is told so; a
//! wrong name or password of this one is not told which.

mod common;

use common::*;

fn params<'a>(f: &'a UserFixture, challenge: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("client_id", f.web.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", REDIRECT),
        ("scope", "openid"),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
    ]
}

#[tokio::test]
async fn a_name_of_another_organisation_is_told_where_accounts_here_end() {
    let s = TestServer::start().await;
    let f = user_fixture(&s).await; // Contoso, contoso.com
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    user_fixture_in(&s, other, "zed@fabrikam.test").await;
    let (_, challenge) = pkce();
    let b = Browser::new();

    for (upn, password, says_where) in [
        // An account that exists, of another tenant.
        ("zed@fabrikam.test", "Correct-Horse-9", true),
        // A domain nobody has: a typo, most likely.
        ("alice@contoso.cmo", "Correct-Horse-9", true),
        // This tenant's own domain: wrong password and unknown name read the same.
        ("alice@contoso.com", "wrong", false),
        ("nobody@contoso.com", "Correct-Horse-9", false),
    ] {
        let login = b.authorize(&s, &f.tenant.id, &params(&f, &challenge)).await;
        let page = b.login(&login, upn, password).await;
        assert_eq!(page.status, 401, "{upn}");
        assert_eq!(
            page.body.contains("Accounts here end in @contoso.com"),
            says_where,
            "{upn}: {}",
            page.body
        );
        assert_eq!(page.body.contains("AADSTS50126"), !says_where, "{upn}: {}", page.body);
        // Never whether the other organisation's account exists.
        assert!(!page.body.contains("Fabrikam"), "{upn}: {}", page.body);
    }

    // My Account says the same.
    let login = b.get(&s.url(&format!("/{}/myaccount", f.tenant.id))).await;
    let page = b.login(&login, "zed@fabrikam.test", "Correct-Horse-9").await;
    assert!(page.body.contains("Accounts here end in @contoso.com"), "{}", page.body);
}

/// The flow tester says whose accounts can sign in to a test, and how to see an
/// API's roles.
#[tokio::test]
async fn the_flow_tester_says_who_can_sign_in_and_how_to_see_roles() {
    let s = TestServer::start().await;
    let f = admin_fixture(&s).await;
    let other = s.tenant("Fabrikam", "fabrikam.test").await;
    let b = signed_in_admin(&s, &f).await;
    // The tester client, so the page has something to run.
    b.post(
        &s.url(&format!("/admin/tenants/{}/flow", other.id)),
        &[("op", "create_test_client")],
    )
    .await;
    let page = b.get(&s.url(&format!("/admin/tenants/{}/flow", other.id))).await;
    assert!(
        page.body
            .contains("Sign in with an account of Fabrikam, one ending in @fabrikam.test"),
        "{}",
        page.body
    );
    assert!(page.body.contains("/.default"), "{}", page.body);
}
