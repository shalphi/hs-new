INSERT INTO merchant_connector_account (
    merchant_id, 
    connector_name, 
    connector_type, 
    connector_account_details, 
    merchant_connector_id,
    profile_id,
    status, 
    created_at, 
    modified_at
) VALUES (
    'merchant_1759413996', 
    'stripe', 
    'payout_processor', 
    '{"api_key":"sk_test_xxx","publishable_key":"pk_test_xxx"}', 
    'mca_stripe_payout_' || extract(epoch from now())::text,
    'pro_BcJTlyd7XwGCSjHELYru',
    'active', 
    NOW(), 
    NOW()
);
