pub mod transformers;
#[cfg(feature = "frm")]
use api_models::webhooks::{ConnectorWebhookSecrets, IncomingWebhookEvent, ObjectReferenceId};
#[cfg(feature = "frm")]
use base64::Engine;
#[cfg(feature = "frm")]
use common_utils::types::{AmountConvertor, StringMajorUnit, StringMajorUnitForConnector};
#[cfg(feature = "frm")]
use common_utils::{
    consts::BASE64_ENGINE,
    request::{Method, RequestBuilder},
    types::MinorUnit,
};
#[cfg(feature = "frm")]
use common_utils::{ext_traits::ByteSliceExt, request::RequestContent};
use common_utils::{errors::CustomResult, request::Request};
#[cfg(feature = "frm")]
use error_stack::ResultExt;
#[cfg(feature = "frm")]
use hyperswitch_domain_models::{
    router_data::ErrorResponse,
    router_flow_types::{Checkout, Fulfillment, RecordReturn, Sale, Transaction},
    router_request_types::fraud_check::{
        FraudCheckCheckoutData, FraudCheckFulfillmentData, FraudCheckRecordReturnData,
        FraudCheckSaleData, FraudCheckTransactionData,
    },
    router_response_types::fraud_check::FraudCheckResponseData,
};
use hyperswitch_domain_models::{
    router_data::{AccessToken, RouterData},
    router_flow_types::{
        AccessTokenAuth, Authorize, Capture, Execute, PSync, PaymentMethodToken, RSync, Session,
        SetupMandate, Void,
    },
    router_request_types::{
        AccessTokenRequestData, PaymentMethodTokenizationData, PaymentsAuthorizeData,
        PaymentsCancelData, PaymentsCaptureData, PaymentsSessionData, PaymentsSyncData,
        RefundsData, SetupMandateRequestData,
    },
    router_response_types::{
        ConnectorInfo, PaymentsResponseData, RefundsResponseData, SupportedPaymentMethods,
    },
};
use hyperswitch_interfaces::{
    api::{
        ConnectorAccessToken, ConnectorCommon, ConnectorCommonExt, ConnectorIntegration,
        ConnectorSpecifications, ConnectorValidation, MandateSetup, Payment, PaymentAuthorize,
        PaymentCapture, PaymentSession, PaymentSync, PaymentToken, PaymentVoid, Refund,
        RefundExecute, RefundSync,
    },
    configs::Connectors,
    errors::ConnectorError,
};
#[cfg(feature = "frm")]
use hyperswitch_interfaces::{
    api::{
        FraudCheck, FraudCheckCheckout, FraudCheckFulfillment, FraudCheckRecordReturn,
        FraudCheckSale, FraudCheckTransaction,
    },
    events::connector_api_logs::ConnectorEvent,
    types::Response,
    webhooks::{IncomingWebhook, IncomingWebhookRequestDetails},
};
#[cfg(feature = "frm")]
use masking::Maskable;
#[cfg(feature = "frm")]
use masking::{ExposeInterface, Secret};
#[cfg(feature = "frm")]
use ring::hmac;
#[cfg(feature = "frm")]
use transformers as riskified2;

#[cfg(feature = "frm")]
use crate::constants::headers;
#[cfg(feature = "frm")]
use crate::utils::convert_amount;
#[cfg(feature = "frm")]
use crate::{
    types::{
        FrmCheckoutRouterData, FrmCheckoutType, FrmFulfillmentRouterData, FrmFulfillmentType,
        FrmTransactionRouterData, FrmTransactionType, ResponseRouterData,
    },
    utils::FraudCheckTransactionRequest,
};

#[derive(Clone)]
pub struct Riskified2 {
    #[cfg(feature = "frm")]
    amount_converter: &'static (dyn AmountConvertor<Output = StringMajorUnit> + Sync),
}

impl Riskified2 {
    pub fn new() -> &'static Self {
        &Self {
            #[cfg(feature = "frm")]
            amount_converter: &StringMajorUnitForConnector,
        }
    }

    #[cfg(feature = "frm")]
    pub fn build_headers(
        &self,
        req: &FrmCheckoutRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        let auth = riskified2::Riskified2AuthType::try_from(&req.connector_auth_type)?;
        let riskified2_req = riskified2::Riskified2PaymentsCheckoutRequest::try_from(&riskified2::Riskified2RouterData::from((
            convert_amount(
                self.amount_converter,
                MinorUnit::new(req.request.amount),
                req.request
                    .currency
                    .ok_or(ConnectorError::MissingRequiredField {
                        field_name: "currency",
                    })?,
            )?,
            req,
        )))?;
        let riskified2_req_json = serde_json::to_string(&riskified2_req)
            .change_context(ConnectorError::RequestEncodingFailed)?;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .change_context(ConnectorError::RequestEncodingFailed)?
            .as_secs()
            .to_string();
        let auth_string = format!(
            "{}{}{}{}{}{}",
            auth.domain_name,
            "POST",
            "/api/decide",
            "application/json",
            timestamp,
            riskified2_req_json
        );
        let signature = self.generate_signature(&auth.secret_token, auth_string.as_bytes())?;
        let auth_header_value = format!(
            "{}:{}:{}",
            auth.domain_name,
            signature.expose(),
            timestamp
        );
        Ok(vec![
            (
                headers::CONTENT_TYPE.to_string(),
                "application/json".to_string().into(),
            ),
            (
                headers::AUTHORIZATION.to_string(),
                auth_header_value.into(),
            ),
        ])
    }

    #[cfg(feature = "frm")]
    fn generate_signature(
        &self,
        secret: &Secret<String>,
        payload: &[u8],
    ) -> CustomResult<Secret<String>, ConnectorError> {
        let key = hmac::Key::new(hmac::HMAC_SHA256, secret.clone().expose().as_bytes());
        let signature = hmac::sign(&key, payload);
        Ok(Secret::new(BASE64_ENGINE.encode(signature.as_ref())))
    }
}



impl ConnectorCommon for Riskified2 {
    fn id(&self) -> &'static str {
        "riskified2"
    }

    // fn get_currency_unit(&self) -> api_models::enums::CurrencyUnit {
    //     api_models::enums::CurrencyUnit::Major
    // }

    fn common_get_content_type(&self) -> &'static str {
        "application/json"
    }

    fn base_url<'a>(&self, connectors: &'a Connectors) -> &'a str {
        connectors.riskified2.base_url.as_ref()
    }

    // #[cfg(feature = "frm")]
    // fn get_base_url(&self, connectors: &Connectors) -> String {
    //     connectors.riskified2.base_url.to_string()
    // }

    fn build_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        use hyperswitch_interfaces::consts::NO_ERROR_CODE;
        let response: riskified2::ErrorResponse = res
            .response
            .parse_struct("Riskified2 ErrorResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;

        event_builder.map(|i| i.set_error_response_body(&response));
        router_env::logger::info!(connector_response=?response);

        Ok(ErrorResponse {
            status_code: res.status_code,
            attempt_status: None,
            code: NO_ERROR_CODE.to_string(),
            message: response.error.message.clone(),
            reason: None,
            connector_transaction_id: None,
            network_advice_code: None,
            network_decline_code: None,
            network_error_message: None,
            connector_metadata: None,
        })
    }
}

impl ConnectorValidation for Riskified2 {}

impl ConnectorCommonExt<FrmCheckoutRouterData, FraudCheckCheckoutData, FraudCheckResponseData>
    for Riskified2
{
}

impl ConnectorCommonExt<FrmTransactionRouterData, FraudCheckTransactionData, FraudCheckResponseData>
    for Riskified2
{
}

impl ConnectorCommonExt<FrmFulfillmentRouterData, FraudCheckFulfillmentData, FraudCheckResponseData>
    for Riskified2
{
}

#[cfg(feature = "frm")]
impl ConnectorIntegration<Checkout, FraudCheckCheckoutData, FraudCheckResponseData> for Riskified2 {
    fn get_headers(
        &self,
        req: &FrmCheckoutRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req, connectors)
    }

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &FrmCheckoutRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!("{}{}", self.base_url(connectors), "/decide"))
    }

    fn get_request_body(
        &self,
        req: &FrmCheckoutRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let amount = convert_amount(
            self.amount_converter,
            MinorUnit::new(req.request.amount),
            req.request
                .currency
                .ok_or(ConnectorError::MissingRequiredField {
                    field_name: "currency",
                })?,
        )?;
        let req_data = riskified2::Riskified2RouterData::from((amount, req));
        let req_obj = riskified2::Riskified2PaymentsCheckoutRequest::try_from(&req_data)?;
        Ok(RequestContent::Json(Box::new(req_obj)))
    }

    fn build_request(
        &self,
        req: &FrmCheckoutRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&FrmCheckoutType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(FrmCheckoutType::get_headers(self, req, connectors)?)
                .set_body(FrmCheckoutType::get_request_body(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &FrmCheckoutRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<FrmCheckoutRouterData, ConnectorError> {
        let response: riskified2::Riskified2PaymentsResponse = res
            .response
            .parse_struct("Riskified2 PaymentsResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

#[cfg(feature = "frm")]
impl ConnectorIntegration<Transaction, FraudCheckTransactionData, FraudCheckResponseData>
    for Riskified2
{
    
    fn get_headers(
        &self,
        req: &FrmTransactionRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req, connectors)
    }
    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &FrmTransactionRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!("{}{}", self.base_url(connectors), "/historical"))
    }

    fn get_request_body(
        &self,
        req: &FrmTransactionRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        match req.is_payment_successful() {
            Some(false) => {
                let req_obj = riskified2::TransactionFailedRequest::try_from(req)?;
                // let req_obj = TransactionFailedRequest::try_from(req)?;
                Ok(RequestContent::Json(Box::new(req_obj)))
            }
            _ => {
                let amount = convert_amount(
                    self.amount_converter,
                    MinorUnit::new(req.request.amount),
                    req.request
                        .currency
                        .ok_or(ConnectorError::MissingRequiredField {
                            field_name: "currency",
                        })?,
                )?;
                let req_data = riskified2::Riskified2RouterData::from((amount, req));
                let req_obj = riskified2::TransactionSuccessRequest::try_from(&req_data)?;
                Ok(RequestContent::Json(Box::new(req_obj)))
            }
        }
        // if req.request.is_success() {
        //     let amount = convert_amount(
        //         self.amount_converter,
        //         MinorUnit::new(req.request.amount),
        //         req.request.get_currency()?,
        //     )?;
        //     let req_obj = riskified2::TransactionSuccessRequest::try_from(&riskified2::Riskified2RouterData::from((amount, req)))?;
        //     Ok(RequestContent::Json(Box::new(req_obj)))
        // } else {
        //     let req_obj = riskified2::TransactionFailedRequest::try_from(req)?;
        //     Ok(RequestContent::Json(Box::new(req_obj)))
        // }
    }

    fn build_request(
        &self,
        req: &FrmTransactionRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&FrmTransactionType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(FrmTransactionType::get_headers(self, req, connectors)?)
                .set_body(FrmTransactionType::get_request_body(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &FrmTransactionRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<FrmTransactionRouterData, ConnectorError> {
        let response: riskified2::Riskified2TransactionResponse = res
            .response
            .parse_struct("Riskified2 TransactionResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        match response {
            riskified2::Riskified2TransactionResponse::FailedResponse(failed_response) => {
                RouterData::try_from(ResponseRouterData {
                    response: failed_response,
                    data: data.clone(),
                    http_code: res.status_code,
                })
            }
            riskified2::Riskified2TransactionResponse::SuccessResponse(success_response) => {
                RouterData::try_from(ResponseRouterData {
                    response: success_response,
                    data: data.clone(),
                    http_code: res.status_code,
                })
            }
        }
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

#[cfg(feature = "frm")]
impl ConnectorIntegration<Fulfillment, FraudCheckFulfillmentData, FraudCheckResponseData>
    for Riskified2
{
    fn get_headers(
        &self,
        req: &FrmFulfillmentRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Vec<(String, Maskable<String>)>, ConnectorError> {
        self.build_headers(req, connectors)
    }
    

    fn get_content_type(&self) -> &'static str {
        self.common_get_content_type()
    }

    fn get_url(
        &self,
        _req: &FrmFulfillmentRouterData,
        connectors: &Connectors,
    ) -> CustomResult<String, ConnectorError> {
        Ok(format!("{}{}", self.base_url(connectors), "/fulfill"))
    }

    fn get_request_body(
        &self,
        req: &FrmFulfillmentRouterData,
        _connectors: &Connectors,
    ) -> CustomResult<RequestContent, ConnectorError> {
        let req_obj = riskified2::Riskified2FulfillmentRequest::try_from(req)?;
        Ok(RequestContent::Json(Box::new(req_obj)))
    }

    fn build_request(
        &self,
        req: &FrmFulfillmentRouterData,
        connectors: &Connectors,
    ) -> CustomResult<Option<Request>, ConnectorError> {
        Ok(Some(
            RequestBuilder::new()
                .method(Method::Post)
                .url(&FrmFulfillmentType::get_url(self, req, connectors)?)
                .attach_default_headers()
                .headers(FrmFulfillmentType::get_headers(self, req, connectors)?)
                .set_body(FrmFulfillmentType::get_request_body(self, req, connectors)?)
                .build(),
        ))
    }

    fn handle_response(
        &self,
        data: &FrmFulfillmentRouterData,
        event_builder: Option<&mut ConnectorEvent>,
        res: Response,
    ) -> CustomResult<FrmFulfillmentRouterData, ConnectorError> {
        let response: riskified2::Riskified2FulfilmentResponse = res
            .response
            .parse_struct("Riskified2 FulfilmentResponse")
            .change_context(ConnectorError::ResponseDeserializationFailed)?;
        event_builder.map(|i| i.set_response_body(&response));
        router_env::logger::info!(connector_response=?response);
        RouterData::try_from(ResponseRouterData {
            response,
            data: data.clone(),
            http_code: res.status_code,
        })
    }

    fn get_error_response(
        &self,
        res: Response,
        event_builder: Option<&mut ConnectorEvent>,
    ) -> CustomResult<ErrorResponse, ConnectorError> {
        self.build_error_response(res, event_builder)
    }
}

impl ConnectorAccessToken for Riskified2 {}

impl ConnectorIntegration<AccessTokenAuth, AccessTokenRequestData, AccessToken> for Riskified2 {}

impl Payment for Riskified2 {}

impl PaymentToken for Riskified2 {}

impl ConnectorIntegration<PaymentMethodToken, PaymentMethodTokenizationData, PaymentsResponseData>
    for Riskified2
{
}

impl PaymentVoid for Riskified2 {}

impl MandateSetup for Riskified2 {}

impl ConnectorIntegration<SetupMandate, SetupMandateRequestData, PaymentsResponseData>
    for Riskified2
{
}

impl PaymentAuthorize for Riskified2 {}

impl PaymentCapture for Riskified2 {}

impl PaymentSession for Riskified2 {}

impl ConnectorIntegration<Session, PaymentsSessionData, PaymentsResponseData> for Riskified2 {}

impl ConnectorIntegration<Capture, PaymentsCaptureData, PaymentsResponseData> for Riskified2 {}

impl ConnectorIntegration<PSync, PaymentsSyncData, PaymentsResponseData> for Riskified2 {}

impl ConnectorIntegration<Authorize, PaymentsAuthorizeData, PaymentsResponseData> for Riskified2 {}

impl ConnectorIntegration<Void, PaymentsCancelData, PaymentsResponseData> for Riskified2 {}

impl ConnectorIntegration<Execute, RefundsData, RefundsResponseData> for Riskified2 {}

impl ConnectorIntegration<RSync, RefundsData, RefundsResponseData> for Riskified2 {}

#[cfg(feature = "frm")]
impl FraudCheck for Riskified2 {}
#[cfg(feature = "frm")]
impl FraudCheckSale for Riskified2 {}
#[cfg(feature = "frm")]
impl FraudCheckCheckout for Riskified2 {}
#[cfg(feature = "frm")]
impl FraudCheckTransaction for Riskified2 {}
#[cfg(feature = "frm")]
impl FraudCheckFulfillment for Riskified2 {}
#[cfg(feature = "frm")]
impl FraudCheckRecordReturn for Riskified2 {}

#[cfg(feature = "frm")]
#[async_trait::async_trait]
impl IncomingWebhook for Riskified2 {
    fn get_webhook_object_reference_id(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<ObjectReferenceId, ConnectorError> {
        let webhook_body: riskified2::Riskified2WebhookBody = request
            .body
            .parse_struct("Riskified2WebhookBody")
            .change_context(ConnectorError::WebhookReferenceIdNotFound)?;
        Ok(ObjectReferenceId::PaymentId(
            api_models::payments::PaymentIdType::ConnectorTransactionId(webhook_body.id),
        ))
    }

    fn get_webhook_event_type(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<IncomingWebhookEvent, ConnectorError> {
        let resource: riskified2::Riskified2WebhookBody = request
            .body
            .parse_struct("Riskified2WebhookBody")
            .change_context(ConnectorError::WebhookEventTypeNotFound)?;
        Ok(IncomingWebhookEvent::from(resource.status))
    }

    fn get_webhook_resource_object(
        &self,
        request: &IncomingWebhookRequestDetails<'_>,
    ) -> CustomResult<Box<dyn masking::ErasedMaskSerialize>, ConnectorError> {
        let resource: riskified2::Riskified2WebhookBody = request
            .body
            .parse_struct("Riskified2WebhookBody")
            .change_context(ConnectorError::WebhookResourceObjectNotFound)?;
        Ok(Box::new(resource))
    }
}

static RISKIFIED2_CONNECTOR_INFO: ConnectorInfo = ConnectorInfo {
    display_name: "Riskified2",
    description: "Riskified2 fraud and risk management provider with guaranteed real-time decisions and machine learning-powered ecommerce fraud prevention",
    connector_type: common_enums::HyperswitchConnectorCategory::FraudAndRiskManagementProvider,
    integration_status: common_enums::ConnectorIntegrationStatus::Sandbox,
};

impl ConnectorSpecifications for Riskified2 {
    fn get_connector_about(&self) -> Option<&'static ConnectorInfo> {
        Some(&RISKIFIED2_CONNECTOR_INFO)
    }

    fn get_supported_payment_methods(&self) -> Option<&'static SupportedPaymentMethods> {
        None
    }

    fn get_supported_webhook_flows(&self) -> Option<&'static [common_enums::enums::EventClass]> {
        None
    }
}
