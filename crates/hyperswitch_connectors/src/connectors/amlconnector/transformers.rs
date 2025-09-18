use chrono;
use common_enums::enums;
use common_utils::types::StringMinorUnit;
use hyperswitch_domain_models::{
    router_data::{ConnectorAuthType, RouterData},
    router_flow_types::refunds::{Execute, RSync},
    router_request_types::{PaymentsCancelData, ResponseId},
    router_response_types::{PaymentsResponseData, RefundsResponseData},
    types::{PaymentsAuthorizeRouterData, PaymentsCaptureRouterData, RefundsRouterData},
};
use hyperswitch_interfaces::errors;
use masking::{ExposeInterface, Secret};
use serde::{Deserialize, Serialize};

use crate::types::{RefundsResponseRouterData, ResponseRouterData};

//TODO: Fill the struct with respective fields
pub struct AmlconnectorRouterData<T> {
    pub amount: StringMinorUnit, // The type of amount that a connector accepts, for example, String, i64, f64, etc.
    pub router_data: T,
}

impl<T> From<(StringMinorUnit, T)> for AmlconnectorRouterData<T> {
    fn from((amount, item): (StringMinorUnit, T)) -> Self {
        //Todo :  use utils to convert the amount to the type of amount that a connector accepts
        Self {
            amount,
            router_data: item,
        }
    }
}

//TODO: Fill the struct with respective fields
#[derive(Default, Debug, Serialize, PartialEq)]
pub struct AmlconnectorPaymentsRequest {
    #[serde(rename = "Client")]
    client: AMLClient,
    #[serde(rename = "Amount")]
    amount: f64,
    #[serde(rename = "ServiceID")]
    service_id: i32,
    #[serde(rename = "ChannelID")]
    channel_id: i32,
    #[serde(rename = "DateTime")]
    date_time: String,
    #[serde(rename = "ShowFullData")]
    show_full_data: i32,
    #[serde(rename = "OuterID", skip_serializing_if = "Option::is_none")]
    outer_id: Option<String>,
    #[serde(rename = "Notes", skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(rename = "Payer", skip_serializing_if = "Option::is_none")]
    payer: Option<AMLPayer>,
    #[serde(rename = "Beneficiary", skip_serializing_if = "Option::is_none")]
    beneficiary: Option<AMLBeneficiary>,
    #[serde(rename = "Person", skip_serializing_if = "Option::is_none")]
    person: Option<AMLPerson>,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct AMLClient {
    #[serde(rename = "Culture")]
    culture: String,
    #[serde(rename = "Login")]
    login: String,
    #[serde(rename = "Hash")]
    hash: String,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct AMLPayer {
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "Account", skip_serializing_if = "Option::is_none")]
    account: Option<String>,
    #[serde(rename = "Type")]
    payer_type: String,
    #[serde(rename = "OuterId", skip_serializing_if = "Option::is_none")]
    outer_id: Option<String>,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct AMLBeneficiary {
    #[serde(rename = "Name", skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(rename = "Account", skip_serializing_if = "Option::is_none")]
    account: Option<String>,
    #[serde(rename = "Type")]
    beneficiary_type: String,
    #[serde(rename = "OuterId", skip_serializing_if = "Option::is_none")]
    outer_id: Option<String>,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct AMLPerson {
    #[serde(rename = "Type")]
    person_type: String,
    #[serde(rename = "FirstName", skip_serializing_if = "Option::is_none")]
    first_name: Option<String>,
    #[serde(rename = "LastName", skip_serializing_if = "Option::is_none")]
    last_name: Option<String>,
    #[serde(rename = "DocNumber", skip_serializing_if = "Option::is_none")]
    doc_number: Option<String>,
    #[serde(rename = "DocCountry", skip_serializing_if = "Option::is_none")]
    doc_country: Option<String>,
    #[serde(rename = "ResidencyCountry", skip_serializing_if = "Option::is_none")]
    residency_country: Option<String>,
    #[serde(rename = "DateOfBirth", skip_serializing_if = "Option::is_none")]
    date_of_birth: Option<String>,
    #[serde(rename = "Account", skip_serializing_if = "Option::is_none")]
    account: Option<String>,
    #[serde(rename = "IP", skip_serializing_if = "Option::is_none")]
    ip: Option<String>,
    #[serde(rename = "FullAddress", skip_serializing_if = "Option::is_none")]
    full_address: Option<String>,
    #[serde(rename = "City", skip_serializing_if = "Option::is_none")]
    city: Option<String>,
    #[serde(rename = "Postal", skip_serializing_if = "Option::is_none")]
    postal: Option<String>,
    #[serde(rename = "Phone", skip_serializing_if = "Option::is_none")]
    phone: Option<String>,
}

impl TryFrom<&AmlconnectorRouterData<&PaymentsAuthorizeRouterData>>
    for AmlconnectorPaymentsRequest
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &AmlconnectorRouterData<&PaymentsAuthorizeRouterData>,
    ) -> Result<Self, Self::Error> {
        let amount_str = item.amount.to_string();
        let amount = amount_str.parse::<f64>()
            .map_err(|_| errors::ConnectorError::InvalidDataFormat {
                field_name: "amount",
            })?;

        let auth = AmlconnectorAuthType::try_from(&item.router_data.connector_auth_type)?;
        
        let current_time = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
        
        Ok(Self {
            client: AMLClient {
                culture: "en".to_string(),
                login: auth.api_key.expose().clone(),
                hash: "test_hash".to_string(), // TODO: implement proper hash generation
            },
            amount: amount / 100.0, // Convert from minor units to major units
            service_id: 1,
            channel_id: 1,
            date_time: current_time,
            show_full_data: 1,
            outer_id: Some(item.router_data.attempt_id.clone()),
            notes: item.router_data.description.clone(),
            payer: None, // TODO: extract from payment data
            beneficiary: None, // TODO: extract from payment data
            person: None, // TODO: extract from customer data
        })
    }
}

//TODO: Fill the struct with respective fields
// Auth Struct
pub struct AmlconnectorAuthType {
    pub(super) api_key: Secret<String>,
}

impl TryFrom<&ConnectorAuthType> for AmlconnectorAuthType {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(auth_type: &ConnectorAuthType) -> Result<Self, Self::Error> {
        match auth_type {
            ConnectorAuthType::HeaderKey { api_key } => Ok(Self {
                api_key: api_key.to_owned(),
            }),
            _ => Err(errors::ConnectorError::FailedToObtainAuthType.into()),
        }
    }
}
// PaymentsResponse
//TODO: Append the remaining status flags
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AmlconnectorPaymentStatus {
    Succeeded,
    Failed,
    #[default]
    Processing,
}

impl From<AmlconnectorPaymentStatus> for common_enums::AttemptStatus {
    fn from(item: AmlconnectorPaymentStatus) -> Self {
        match item {
            AmlconnectorPaymentStatus::Succeeded => Self::Charged,
            AmlconnectorPaymentStatus::Failed => Self::Failure,
            AmlconnectorPaymentStatus::Processing => Self::Authorizing,
        }
    }
}

//TODO: Fill the struct with respective fields
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AmlconnectorPaymentsResponse {
    #[serde(rename = "Result")]
    result: i32,
    #[serde(rename = "ErrorCode")]
    error_code: i32,
    #[serde(rename = "ErrorCodeExt")]
    error_code_ext: Option<String>,
    #[serde(rename = "ErrorText")]
    error_text: Option<String>,
    #[serde(rename = "Ticket")]
    ticket: Option<String>,
    #[serde(rename = "ResultExt")]
    result_ext: Option<String>,
    #[serde(rename = "ApplySpecialFee")]
    apply_special_fee: Option<String>,
    #[serde(rename = "PrevChannelID")]
    prev_channel_id: Option<String>,
    #[serde(rename = "ChannelID")]
    channel_id: Option<String>,
    #[serde(rename = "StructuredErrorText")]
    structured_error_text: Option<String>,
    #[serde(rename = "AppliedLimits")]
    applied_limits: Option<String>,
    #[serde(rename = "AvailableAmountSpecified")]
    available_amount_specified: Option<String>,
    #[serde(rename = "AvailableCountSpecified")]
    available_count_specified: Option<String>,
}

impl<F, T> TryFrom<ResponseRouterData<F, AmlconnectorPaymentsResponse, T, PaymentsResponseData>>
    for RouterData<F, T, PaymentsResponseData>
{
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: ResponseRouterData<F, AmlconnectorPaymentsResponse, T, PaymentsResponseData>,
    ) -> Result<Self, Self::Error> {
        let status = match item.response.result {
            1 => common_enums::AttemptStatus::Charged, // Success
            0 => common_enums::AttemptStatus::Failure,  // Fail
            2 => common_enums::AttemptStatus::Pending,  // Warning
            _ => common_enums::AttemptStatus::Failure,  // Default to failure for unknown status
        };

        let transaction_id = item.response.ticket
            .clone()
            .unwrap_or_else(|| format!("aml_{}", item.response.result));

        Ok(Self {
            status,
            response: Ok(PaymentsResponseData::TransactionResponse {
                resource_id: ResponseId::ConnectorTransactionId(transaction_id),
                redirection_data: Box::new(None),
                mandate_reference: Box::new(None),
                connector_metadata: None,
                network_txn_id: None,
                connector_response_reference_id: None,
                incremental_authorization_allowed: None,
                charges: None,
            }),
            ..item.data
        })
    }
}

//TODO: Fill the struct with respective fields
// REFUND :
// Type definition for RefundRequest
#[derive(Default, Debug, Serialize)]
pub struct AmlconnectorRefundRequest {
    pub amount: StringMinorUnit,
}

impl<F> TryFrom<&AmlconnectorRouterData<&RefundsRouterData<F>>> for AmlconnectorRefundRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &AmlconnectorRouterData<&RefundsRouterData<F>>) -> Result<Self, Self::Error> {
        Ok(Self {
            amount: item.amount.to_owned(),
        })
    }
}

// Type definition for Refund Response

#[allow(dead_code)]
#[derive(Debug, Copy, Serialize, Default, Deserialize, Clone)]
pub enum RefundStatus {
    Succeeded,
    Failed,
    #[default]
    Processing,
}

impl From<RefundStatus> for enums::RefundStatus {
    fn from(item: RefundStatus) -> Self {
        match item {
            RefundStatus::Succeeded => Self::Success,
            RefundStatus::Failed => Self::Failure,
            RefundStatus::Processing => Self::Pending,
            //TODO: Review mapping
        }
    }
}

//TODO: Fill the struct with respective fields
#[derive(Default, Debug, Clone, Serialize, Deserialize)]
pub struct RefundResponse {
    id: String,
    status: RefundStatus,
}

impl TryFrom<RefundsResponseRouterData<Execute, RefundResponse>> for RefundsRouterData<Execute> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<Execute, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
    }
}

impl TryFrom<RefundsResponseRouterData<RSync, RefundResponse>> for RefundsRouterData<RSync> {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: RefundsResponseRouterData<RSync, RefundResponse>,
    ) -> Result<Self, Self::Error> {
        Ok(Self {
            response: Ok(RefundsResponseData {
                connector_refund_id: item.response.id.to_string(),
                refund_status: enums::RefundStatus::from(item.response.status),
            }),
            ..item.data
        })
    }
}

//TODO: Fill the struct with respective fields
//TODO: Fill the struct with respective fields
#[derive(Default, Debug, Serialize, Deserialize, PartialEq)]
pub struct AmlconnectorErrorResponse {
    pub status_code: u16,
    pub code: String,
    pub message: String,
    pub reason: Option<String>,
    pub network_advice_code: Option<String>,
    pub network_decline_code: Option<String>,
    pub network_error_message: Option<String>,
}

// Additional AML-specific request structures for different operations

#[derive(Default, Debug, Serialize, PartialEq)]
pub struct AMLMakePaymentRequest {
    #[serde(rename = "Client")]
    client: AMLClient,
    #[serde(rename = "Amount")]
    amount: f64,
    #[serde(rename = "ServiceID")]
    service_id: i32,
    #[serde(rename = "ChannelID")]
    channel_id: i32,
    #[serde(rename = "DateTime")]
    date_time: String,
    #[serde(rename = "ShowFullData")]
    show_full_data: i32,
    #[serde(rename = "OuterID", skip_serializing_if = "Option::is_none")]
    outer_id: Option<String>,
    #[serde(rename = "Notes", skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
    #[serde(rename = "Payer", skip_serializing_if = "Option::is_none")]
    payer: Option<AMLPayer>,
    #[serde(rename = "Beneficiary", skip_serializing_if = "Option::is_none")]
    beneficiary: Option<AMLBeneficiary>,
    #[serde(rename = "Person", skip_serializing_if = "Option::is_none")]
    person: Option<AMLPerson>,
}

#[derive(Default, Debug, Serialize, PartialEq)]
pub struct CheckPEPRequest {
    #[serde(rename = "Client")]
    client: AMLClient,
    #[serde(rename = "Person")]
    person: AMLPerson,
    #[serde(rename = "DateTime")]
    date_time: String,
    #[serde(rename = "ShowFullData")]
    show_full_data: i32,
}

#[derive(Default, Debug, Serialize, PartialEq)]
pub struct CheckWatchBlackRequest {
    #[serde(rename = "Client")]
    client: AMLClient,
    #[serde(rename = "Person")]
    person: AMLPerson,
    #[serde(rename = "DateTime")]
    date_time: String,
    #[serde(rename = "ShowFullData")]
    show_full_data: i32,
}

#[derive(Default, Debug, Serialize, PartialEq)]
pub struct CheckCTFRequest {
    #[serde(rename = "Client")]
    client: AMLClient,
    #[serde(rename = "Person")]
    person: AMLPerson,
    #[serde(rename = "DateTime")]
    date_time: String,
    #[serde(rename = "ShowFullData")]
    show_full_data: i32,
}

#[derive(Default, Debug, Serialize, PartialEq)]
pub struct AMLRollbackRequest {
    #[serde(rename = "Client")]
    client: AMLClient,
    #[serde(rename = "Amount")]
    amount: Option<f64>,
    #[serde(rename = "ServiceID")]
    service_id: i32,
    #[serde(rename = "ChannelID")]
    channel_id: i32,
    #[serde(rename = "OuterID", skip_serializing_if = "Option::is_none")]
    outer_id: Option<String>,
}

#[derive(Default, Debug, Serialize, PartialEq)]
pub struct AddToWhiteListRequest {
    #[serde(rename = "Client")]
    client: AMLWhiteListClient,
    #[serde(rename = "Ticket", skip_serializing_if = "Option::is_none")]
    ticket: Option<String>,
    #[serde(rename = "Officer", skip_serializing_if = "Option::is_none")]
    officer: Option<String>,
}

#[derive(Default, Debug, Serialize, Eq, PartialEq)]
pub struct AMLWhiteListClient {
    #[serde(rename = "Culture")]
    culture: String,
    #[serde(rename = "Login")]
    login: String,
    #[serde(rename = "Hash")]
    hash: String,
}

// Response structures for rollback operations
#[derive(Default, Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AMLRollbackResponse {
    #[serde(rename = "Result")]
    pub result: i32,
    #[serde(rename = "ErrorCode")]
    pub error_code: i32,
    #[serde(rename = "ErrorCodeExt")]
    pub error_code_ext: Option<String>,
    #[serde(rename = "ErrorText")]
    pub error_text: Option<String>,
    #[serde(rename = "ResultExt")]
    pub result_ext: Option<String>,
}

// TryFrom implementations for new AML operations

impl TryFrom<&AmlconnectorRouterData<&PaymentsCaptureRouterData>> for AMLMakePaymentRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(
        item: &AmlconnectorRouterData<&PaymentsCaptureRouterData>,
    ) -> Result<Self, Self::Error> {
        let amount_str = item.amount.to_string();
        let amount = amount_str.parse::<f64>()
            .map_err(|_| errors::ConnectorError::InvalidDataFormat {
                field_name: "amount",
            })?;

        let auth = AmlconnectorAuthType::try_from(&item.router_data.connector_auth_type)?;
        let current_time = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S").to_string();
        
        Ok(Self {
            client: AMLClient {
                culture: "en".to_string(),
                login: auth.api_key.expose().clone(),
                hash: "test_hash".to_string(),
            },
            amount: amount / 100.0, // Convert from minor units to major units
            service_id: 1,
            channel_id: 1,
            date_time: current_time,
            show_full_data: 1,
            outer_id: Some(item.router_data.attempt_id.clone()),
            notes: None, // PaymentsCaptureData doesn't have reason field
            payer: None,
            beneficiary: None,
            person: None,
        })
    }
}

impl<F> TryFrom<&RouterData<F, PaymentsCancelData, PaymentsResponseData>> for AMLRollbackRequest {
    type Error = error_stack::Report<errors::ConnectorError>;
    fn try_from(item: &RouterData<F, PaymentsCancelData, PaymentsResponseData>) -> Result<Self, Self::Error> {
        let auth = AmlconnectorAuthType::try_from(&item.connector_auth_type)?;
        
        Ok(Self {
            client: AMLClient {
                culture: "en".to_string(),
                login: auth.api_key.expose().clone(),
                hash: "test_hash".to_string(),
            },
            amount: None, // For rollback, amount can be optional
            service_id: 1,
            channel_id: 1,
            outer_id: Some(item.attempt_id.clone()),
        })
    }
}
