#!/bin/bash

echo "💳 Тестовый платеж через Hyperswitch API с API ключом"
echo "====================================================="
echo ""

API_URL="http://localhost:8080"
API_KEY="dev_TE6vDYRxFLd3A2cnRZLkaG2jKSu6XSMhGLxNpXW6m1SZhhm0JOUGIgslObRdioTM"

echo "📊 Данные для платежа:"
echo "- API Key: ${API_KEY:0:20}..."
echo "- API URL: $API_URL"
echo ""

# Создаем тестовый платеж
echo "🚀 Создаем тестовый платеж..."
PAYMENT_PAYLOAD='{
  "amount": 1000,
  "currency": "USD",
  "customer_id": "test_customer_123",
  "description": "Test payment for FRM via API",
  "payment_method": "card",
  "payment_method_data": {
    "card": {
      "card_number": "4242424242424242",
      "card_exp_month": "12",
      "card_exp_year": "2025",
      "card_holder_name": "Test User",
      "card_cvc": "123"
    }
  },
  "frm_metadata": {
    "vendor_name": "Test Store",
    "shipping_lines": [
      {
        "price": "0.00",
        "title": "Free Shipping"
      }
    ]
  },
  "billing": {
    "address": {
      "line1": "123 Test Street",
      "line2": "Apt 4B",
      "city": "New York",
      "state": "NY",
      "zip": "10001",
      "country": "US"
    },
    "name": "Test User"
  },
  "shipping": {
    "address": {
      "line1": "456 Shipping Street",
      "line2": "Suite 2A",
      "city": "New York",
      "state": "NY",
      "zip": "10002",
      "country": "US"
    },
    "name": "Test User"
  },
  "order_details": [
    {
      "product_name": "Test Product",
      "quantity": 1,
      "amount": 1000,
      "currency": "USD"
    }
  ]
}'

echo "📝 Отправляем запрос на создание платежа..."
PAYMENT_RESPONSE=$(curl -s -X POST \
  -H "Content-Type: application/json" \
  -H "api-key: $API_KEY" \
  -d "$PAYMENT_PAYLOAD" \
  "$API_URL/payments")

echo "📋 Ответ на создание платежа:"
echo "$PAYMENT_RESPONSE" | jq . 2>/dev/null || echo "$PAYMENT_RESPONSE"

# Извлекаем payment_id
PAYMENT_ID=$(echo "$PAYMENT_RESPONSE" | grep -o '"payment_id":"[^"]*"' | cut -d'"' -f4)

if [ -n "$PAYMENT_ID" ]; then
    echo ""
    echo "✅ Платеж создан: $PAYMENT_ID"
    echo ""
    
    # Подтверждаем платеж
    echo "🔐 Подтверждаем платеж..."
    CONFIRM_RESPONSE=$(curl -s -X POST \
      -H "Content-Type: application/json" \
      -H "api-key: $API_KEY" \
      -d '{"confirm": true}' \
      "$API_URL/payments/$PAYMENT_ID/confirm")
    
    echo "📋 Ответ на подтверждение платежа:"
    echo "$CONFIRM_RESPONSE" | jq . 2>/dev/null || echo "$CONFIRM_RESPONSE"
    
    echo ""
    echo "🔍 Проверяем FRM данные в базе..."
    echo ""
    
    # Проверяем fraud_check записи
    echo "📊 Fraud check записи:"
    docker exec hs-new-pg-1 psql -U db_user -d hyperswitch_db -c "SELECT frm_id, payment_id, frm_name, frm_status, frm_transaction_type, created_at FROM fraud_check WHERE payment_id = '$PAYMENT_ID';" 2>/dev/null
    
    echo ""
    echo "📊 Детали платежа в базе:"
    docker exec hs-new-pg-1 psql -U db_user -d hyperswitch_db -c "SELECT payment_id, status, amount, currency, connector, frm_message, merchant_decision FROM payment_intent WHERE payment_id = '$PAYMENT_ID';" 2>/dev/null
    
    echo ""
    echo "🧪 Проверяем логи FRM..."
    echo "Последние записи о FRM в логах:"
    docker logs hs-new-hyperswitch-server-1 --tail 50 | grep -i "frm\|fraud\|riskified" | tail -10
    
else
    echo "❌ Не удалось создать платеж"
    echo "Ответ: $PAYMENT_RESPONSE"
fi

echo ""
echo "✅ Тест завершен!"
