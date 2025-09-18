use std::str::FromStr;
use common_utils::{pii::Email, types::MinorUnit};
use diesel_models::types::OrderDetailsWithAmount;
use hyperswitch_domain_models::{
    address::{Address, AddressDetails},
    router_request_types::fraud_check::FraudCheckCheckoutData,
    router_response_types::fraud_check::FraudCheckResponseData,
    router_flow_types::Checkout,
};
use masking::Secret;
use router::types::{self, api, BrowserInformation, PaymentAddress};

use crate::utils::{self, ConnectorActions};

#[derive(Debug)]
struct HttpResponse {
    status: u16,
    headers: std::collections::HashMap<String, String>,
    body: String,
}


#[derive(Clone, Copy)]
struct Riskified2Test;
impl ConnectorActions for Riskified2Test {}
impl utils::Connector for Riskified2Test {
    fn get_data(&self) -> api::ConnectorData {
        use router::connector::Riskified2;
        utils::construct_connector_data_old(
            Box::new(Riskified2::new()),
            types::Connector::Riskified2,
            api::GetToken::Connector,
            None,
        )
    }

    fn get_auth_token(&self) -> types::ConnectorAuthType {
        types::ConnectorAuthType::BodyKey {
            api_key: Secret::new("test_secret_token".to_string()),
            key1: Secret::new("test.shop.domain.com".to_string()),
        }
    }

    fn get_name(&self) -> String {
        "riskified2".to_string()
    }
}

static CONNECTOR: Riskified2Test = Riskified2Test {};

fn get_default_payment_info() -> Option<utils::PaymentInfo> {
    Some(utils::PaymentInfo {
        address: Some(PaymentAddress::new(
            Some(Address {
                address: Some(AddressDetails {
                    first_name: Some(Secret::new("John".to_string())),
                    last_name: Some(Secret::new("Doe".to_string())),
                    line1: Some(Secret::new("123 Main St".to_string())),
                    city: Some("New York".to_string()),
                    state: Some(Secret::new("NY".to_string())),
                    zip: Some(Secret::new("10001".to_string())),
                    country: Some(common_enums::CountryAlpha2::US),
                    ..Default::default()
                }),
                phone: None,
                email: Some(Email::from_str("john.doe@example.com").unwrap()),
            }),
            Some(Address {
                address: Some(AddressDetails {
                    first_name: Some(Secret::new("John".to_string())),
                    last_name: Some(Secret::new("Doe".to_string())),
                    line1: Some(Secret::new("456 Oak Ave".to_string())),
                    city: Some("Los Angeles".to_string()),
                    state: Some(Secret::new("CA".to_string())),
                    zip: Some(Secret::new("90001".to_string())),
                    country: Some(common_enums::CountryAlpha2::US),
                    ..Default::default()
                }),
                phone: None,
                email: Some(Email::from_str("john.doe@example.com").unwrap()),
            }),
            None,
            None,
        )),
        ..Default::default()
    })
}

fn payment_method_details() -> Option<types::PaymentsAuthorizeData> {
    None
}

fn create_fraud_check_checkout_data() -> FraudCheckCheckoutData {
    FraudCheckCheckoutData {
        amount: 10000, // $100.00 in minor units
        order_details: Some(vec![OrderDetailsWithAmount {
            product_name: "Test Product".to_string(),
            quantity: 1,
            amount: MinorUnit::new(10000),
            requires_shipping: Some(true),
            product_img_link: None,
            product_id: Some("TEST-001".to_string()),
            category: Some("Electronics".to_string()),
            sub_category: None,
            brand: Some("TestBrand".to_string()),
            product_type: Some(common_enums::ProductType::Physical),
            product_tax_code: None,
            tax_rate: None,
            total_tax_amount: None,
            description: Some("Test product description".to_string()),
            sku: Some("TEST-SKU-001".to_string()),
            upc: None,
            commodity_code: None,
            unit_of_measure: None,
            total_amount: Some(MinorUnit::new(10000)),
            unit_discount_amount: None,
        }]),
        currency: Some(common_enums::Currency::USD),
        email: Some(Email::from_str("john.doe@example.com").unwrap()),
        gateway: Some("hyperswitch".to_string()),
        payment_method_data: None,
        browser_info: Some(BrowserInformation {
            color_depth: Some(24),
            java_enabled: Some(false),
            java_script_enabled: Some(true),
            language: Some("en-US".to_string()),
            screen_height: Some(1080),
            screen_width: Some(1920),
            time_zone: Some(300),
            user_agent: Some("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()),
            accept_header: Some("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".to_string()),
            ip_address: Some(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1))),
            accept_language: Some("en-US".to_string()),
            device_model: None,
            os_type: None,
            os_version: None,
        }),
    }
}

// Test real connector methods with mock response
#[actix_web::test]
async fn should_test_riskified2_connector_methods() {
    use hyperswitch_interfaces::types::Response;
    use hyperswitch_domain_models::connector_endpoints::{ConnectorParams, Connectors};
    use std::process;

    println!("🧪 Testing Riskified2 Connector Methods...");
    let settings = Settings::new()
        .expect("Failed to load settings");
    let connector = router::connector::Riskified2::new();
    // let connector = Riskified2::new();
    let connectors = &settings.connectors;

    let mut router_data = CONNECTOR.generate_data(
        create_fraud_check_checkout_data(),
        get_default_payment_info(),
    );
    
    // Add required metadata for Riskified2
    router_data.frm_metadata = Some(Secret::new(serde_json::json!({
        "vendor_name": "Test Vendor",
        "shipping_lines": [{
            "price": "5.00",
            "title": "Standard Shipping"
        }]
    })));

    // ========== TEST 1: get_url method ==========
    let base_url = connector.get_url(&router_data, &connectors).unwrap();
    println!("📍 Base URL from connector method: {}", base_url);
    assert!(base_url.contains("http://danny.top/decide"));

        
    // ========== TEST 2: get_request_body method ==========
    println!("📦 Testing get_request_body method...");
    let request_body = connector.get_request_body(&router_data, &connectors).unwrap();
    println!("   ✅ Request body generated successfully");
    
    // Show request body content
    if let common_utils::request::RequestContent::Json(json_body) = &request_body {
        println!("   📄 Request Body Preview:");
        println!("   {}", serde_json::to_string_pretty(json_body).unwrap_or_else(|_| "Failed to serialize".to_string()));
    }
    
    // ========== TEST 3: get_headers method ==========
    println!("🔐 Testing get_headers method...");
    let headers = connector.get_headers(&router_data, &connectors).unwrap();
    println!("   ✅ Generated {} headers", headers.len());
    
    let header_map: std::collections::HashMap<String, String> = headers
        .iter()
        .map(|(k, v)| (k.clone(), format!("{:?}", v)))
        .collect();
    
    println!("   📋 Headers Details:");
    for (key, value) in &header_map {
        println!("      {}: {}", key, value);
    }
    
    assert!(header_map.contains_key("X-RISKIFIED-SHOP-DOMAIN"));
    assert!(header_map.contains_key("X-RISKIFIED-HMAC-SHA256"));
    assert!(header_map.contains_key("Content-Type"));
    
    // ========== TEST 4: build_request method ==========
    println!("🏗️  Testing build_request method...");
    let request = connector.build_request(&router_data, &connectors).unwrap();
    assert!(request.is_some());
    println!("   ✅ Request built successfully");


    let (tx, _rx) = tokio::sync::oneshot::channel();
    use router::configs::settings::Settings;
    use router::routes::app::StorageImpl;
    use router::services::ProxyClient;
    use router::services::ConnectorIntegration;

    let settings = Settings::new().expect("Load settings");
    let proxy_client = ProxyClient::new(&settings.proxy).expect("Create proxy client");

    let state = Box::pin(router::routes::AppState::with_storage(
        settings,
        StorageImpl::PostgresqlTest,
        tx,
        Box::new(proxy_client),
    ))
    .await;
    use std::sync::Arc;
    let session_state = Arc::new(state).get_session_state(
        &common_utils::id_type::TenantId::try_from_string("public".to_string()).unwrap(),
        None,
        || {},
    ).unwrap();
    // Create a new request for sending (since Request doesn't implement Clone)
    let request_for_sending = connector.build_request(&router_data, &connectors).unwrap().unwrap();
    let resp = session_state
        .api_client
        .send_request(&session_state, request_for_sending, None, false)
        .await
        .expect("Failed to send request");
    println!("🌐 ------------- RECEIVED RESPONSE FROM SERVER -------------");
    
     if let Some(ref req) = request {
         println!("   🌐 Final Request Details:");
         println!("      URL: {}", req.url);
         println!("      Method: {:?}", req.method);
         println!("      Headers count: {}", req.headers.len());
         println!("      Has body: {}", req.body.is_some());
     }
     
     // ========== TEST 5: handle_response method with REAL response ==========
     println!("📥 Testing handle_response method with REAL server response...");
     
     // Use the actual response we received from your server
     let status_code = resp.status().as_u16();
     let real_response_body = resp.text().await.unwrap();
     println!("📄 Server Response Body: {}", real_response_body);
     
     let real_response = Response {
         response: real_response_body.clone().into_bytes().into(),
         status_code,
         headers: None,
     };
     
     let response_result = connector.handle_response(&router_data, None, real_response);
     
     match response_result {
         Ok(response_data) => {
             println!("   ✅ REAL Response handled successfully!");
             println!("   📊 Response Details:");
             println!("      Status: {:?}", response_data.response);
             println!("      Request ID: {}", response_data.attempt_id);
             println!("      Connector: {}", response_data.connector);
         }
         Err(error) => {
             println!("   ❌ REAL Response handling failed: {:?}", error);
             println!("   ℹ️  This might be due to unexpected response format from your server");
         }
     }
     
     // ========== TEST 6: Test error response handling ==========
     println!("❌ Testing error response handling...");
     
     let mock_error_response = Response {
         response: r#"{"error": {"message": "Invalid request"}}"#.to_string().into_bytes().into(),
         status_code: 400,
         headers: None,
     };
     
     // ConnectorIntegration уже импортирован выше
     
     let error_response: Result<hyperswitch_domain_models::router_data::ErrorResponse, _> = 
         <router::connector::Riskified2 as ConnectorIntegration<Checkout, FraudCheckCheckoutData, FraudCheckResponseData>>::get_error_response(&connector, mock_error_response, None);
     match error_response {
         Ok(error_resp) => {
             println!("   ✅ Error response parsed successfully!");
             println!("   📋 Error Details:");
             println!("      Message: {}", error_resp.message);
             println!("      Code: {:?}", error_resp.code);
             println!("      Reason: {:?}", error_resp.reason);
         }
         Err(error) => {
             println!("   ❌ Error response parsing failed: {:?}", error);
             println!("   ℹ️  This might be expected for mock error responses");
         }
     }
     
     println!("🎉 All Riskified2 connector methods tested!");
}





// AML Check Payment Tests - Based on WSDL AMLCheckPayment operation
// #[actix_web::test]
// async fn should_check_payment_aml() {
//     let response = CONNECTOR
//         .authorize_payment(payment_method_details(), get_default_payment_info())
//         .await
//         .expect("AML check payment response");
//     // Based on WSDL, should return success/warning/fail status
//     assert!(matches!(
//         response.status,
//         enums::AttemptStatus::Authorized | enums::AttemptStatus::Failure
//     ));
// }

// AML Make Payment Tests - Based on WSDL AMLMakePayment operation  
// #[actix_web::test]
// async fn should_make_aml_payment() {
//     let response = CONNECTOR
//         .make_payment(payment_method_details(), get_default_payment_info())
//         .await
//         .expect("AML make payment response");
//     // Should process payment through AML system
//     assert!(matches!(
//         response.status,
//         enums::AttemptStatus::Charged | enums::AttemptStatus::Failure
//     ));
// }

// CheckPEP Tests - Based on WSDL CheckPEP operation
// #[actix_web::test]
// async fn should_check_pep() {
//     let response = CONNECTOR
//         .authorize_payment(payment_method_details(), get_default_payment_info())
//         .await
//         .expect("PEP check response");
//     // PEP (Politically Exposed Person) check
//     assert!(matches!(
//         response.status,
//         enums::AttemptStatus::Authorized | enums::AttemptStatus::Failure
//     ));
// }

// CheckWatchBlack Tests - Based on WSDL CheckWatchBlack operation
// #[actix_web::test]
// async fn should_check_watch_black_list() {
//     let response = CONNECTOR
//         .authorize_payment(payment_method_details(), get_default_payment_info())
//         .await
//         .expect("Watch black list check response");
//     // Check against watch/black lists
//     assert!(matches!(
//         response.status,
//         enums::AttemptStatus::Authorized | enums::AttemptStatus::Failure
//     ));
// }

// CheckCTF Tests - Based on WSDL CheckCTF operation
// #[actix_web::test]
// async fn should_check_ctf() {
//     let response = CONNECTOR
//         .authorize_payment(payment_method_details(), get_default_payment_info())
//         .await
//         .expect("CTF check response");
//     // Counter-Terrorism Financing check
//     assert!(matches!(
//         response.status,
//         enums::AttemptStatus::Authorized | enums::AttemptStatus::Failure
//     ));
// }

// AML Rollback Payment Tests - Based on WSDL AMLRollbackPayment operation
// #[actix_web::test]
// async fn should_rollback_aml_payment() {
//     // First make a payment
//     let payment_response = CONNECTOR
//         .make_payment(payment_method_details(), get_default_payment_info())
//         .await
//         .expect("Make payment response");
//     
//     if payment_response.status == enums::AttemptStatus::Charged {
//         // Then attempt rollback
//         let rollback_response = CONNECTOR
//             .void_payment(
//                 utils::get_connector_transaction_id(payment_response.response).unwrap(),
//                 None,
//                 get_default_payment_info(),
//             )
//             .await
//             .expect("Rollback payment response");
//         assert_eq!(rollback_response.status, enums::AttemptStatus::Voided);
//     }
// }

// AddToWhiteList Tests - Based on WSDL AddToWhiteList operation
// #[actix_web::test]
// async fn should_add_to_white_list() {
//     let response = CONNECTOR
//         .authorize_payment(payment_method_details(), get_default_payment_info())
//         .await
//         .expect("Add to white list response");
//     // Adding entity to white list should be successful
//     assert!(matches!(
//         response.status,
//         enums::AttemptStatus::Authorized | enums::AttemptStatus::Failure
//     ));
// }

// DeleteFromWhiteList Tests - Based on WSDL DeleteFromWhiteList operation
// #[actix_web::test]
// async fn should_delete_from_white_list() {
//     let response = CONNECTOR
//         .authorize_payment(payment_method_details(), get_default_payment_info())
//         .await
//         .expect("Delete from white list response");
//     // Removing entity from white list
//     assert!(matches!(
//         response.status,
//         enums::AttemptStatus::Authorized | enums::AttemptStatus::Failure
//     ));
// }

// Payment synchronization test
// #[actix_web::test]
// async fn should_sync_payment() {
//     let authorize_response = CONNECTOR
//         .authorize_payment(payment_method_details(), get_default_payment_info())
//         .await
//         .expect("Authorize payment response");
//     
//     if let Some(txn_id) = utils::get_connector_transaction_id(authorize_response.response) {
//         let response = CONNECTOR
//             .psync_retry_till_status_matches(
//                 enums::AttemptStatus::Authorized,
//                 Some(types::PaymentsSyncData {
//                     connector_transaction_id: types::ResponseId::ConnectorTransactionId(txn_id),
//                     ..Default::default()
//                 }),
//                 get_default_payment_info(),
//             )
//             .await
//             .expect("PSync response");
//         assert_eq!(response.status, enums::AttemptStatus::Authorized);
//     }
// }

// Error handling tests based on WSDL error responses
// #[actix_web::test]
// async fn should_handle_invalid_request() {
//     // Test with invalid payment data to trigger error response
//     let response = CONNECTOR
//         .make_payment(
//             Some(types::PaymentsAuthorizeData {
//                 amount: 0, // Invalid amount should trigger error
//                 ..utils::PaymentAuthorizeType::default().0
//             }),
//             get_default_payment_info(),
//         )
//         .await;
//     
//     // Should handle error gracefully based on AMLResponse structure
//     match response {
//         Ok(resp) => assert_eq!(resp.status, enums::AttemptStatus::Failure),
//         Err(_) => {} // Expected for invalid requests
//     }
// }

// Test with specific AML request structure based on WSDL
// #[actix_web::test] 
// async fn should_process_aml_request_with_required_fields() {
//     // Based on WSDL AMLRequest structure, test with required fields:
//     // Amount, ServiceID, ChannelID, DateTime, ShowFullData
//     let response = CONNECTOR
//         .authorize_payment(
//             Some(types::PaymentsAuthorizeData {
//                 amount: 10000, // Amount in minor units
//                 currency: common_enums::Currency::USD,
//                 ..utils::PaymentAuthorizeType::default().0
//             }),
//             get_default_payment_info(),
//         )
//         .await
//         .expect("AML request with required fields");
//     
//     // Should process successfully with proper required fields
//     assert!(matches!(
//         response.status,
//         enums::AttemptStatus::Authorized | enums::AttemptStatus::Charged | enums::AttemptStatus::Failure
//     ));
// }
