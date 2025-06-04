from ninja_extra import NinjaExtraAPI
from ninja_jwt.controller import NinjaJWTDefaultController
from ninja_jwt.authentication import JWTAuth
from authe.api import router as authe_router

# Initialize API
api = NinjaExtraAPI(auth=JWTAuth())

# Register Controller
api.register_controllers(NinjaJWTDefaultController)

# Add Routers
api.add_router("/authe", authe_router)