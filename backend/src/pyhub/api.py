from ninja_extra import NinjaExtraAPI
from ninja_jwt.controller import NinjaJWTDefaultController
from ninja_jwt.authentication import JWTAuth

# Initialize API
api = NinjaExtraAPI(auth=JWTAuth())

# Register Controller
api.register_controllers(NinjaJWTDefaultController)

# Add Routers
