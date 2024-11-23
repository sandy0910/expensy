from cashfree_pg.models.create_order_request import CreateOrderRequest
from cashfree_pg.api_client import Cashfree
from cashfree_pg.models.customer_details import CustomerDetails


Cashfree.XClientId = {Client ID}
Cashfree.XClientSecret = {Client Secret Key}
Cashfree.XEnvironment = Cashfree.XSandbox
x_api_version = "2023-08-01"

def create_order():
        customerDetails = CustomerDetails(customer_id="123", customer_phone="9999999999")
        createOrderRequest = CreateOrderRequest(order_amount=1, order_currency="INR", customer_details=customerDetails)
        try:
            api_response = Cashfree().PGCreateOrder(x_api_version, createOrderRequest, None, None)
            print(api_response.data)
        except Exception as e:
            print(e)