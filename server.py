import json
from os import environ as env
from urllib.parse import urlparse
import requests

from auth0_server_python.auth_server.server_client import ServerClient
from auth0_server_python.auth_types import LogoutOptions, StartInteractiveLoginOptions, StateData, TransactionData
from auth0_server_python.store.abstract import AbstractDataStore
from dotenv import load_dotenv
from flask import Flask, after_this_request, redirect, request
from markupsafe import escape

load_dotenv()

app = Flask(__name__)


class CookieStore(AbstractDataStore):
    def __init__(self, secret, cookie_name, max_age, model):
        super().__init__({"secret": secret})
        self.cookie_name = cookie_name
        self.max_age = max_age
        self.model = model

    async def set(self, identifier, state, **_):
        @after_this_request
        def apply(response):
            data = state.model_dump() if hasattr(state, "model_dump") else state
            response.set_cookie(
                self.cookie_name,
                self.encrypt(identifier, data),
                httponly=True,
                samesite="Lax",
                secure=not env.get("APP_BASE_URL", "").startswith("http://"),
                max_age=self.max_age,
            )
            return response

    async def get(self, identifier, options=None):
        try:
            encrypted = options["request"].cookies.get(self.cookie_name)
            return self.model.model_validate(self.decrypt(identifier, encrypted)) if encrypted else None
        except Exception:
            app.logger.warning("Failed to decrypt cookie %s", self.cookie_name, exc_info=True)
            return None

    async def delete(self, *_, **__):
        @after_this_request
        def apply(response):
            response.delete_cookie(self.cookie_name)
            return response


def auth0():
    session_secret = env.get("AUTH0_SECRET")

    return ServerClient(
        domain=env.get("AUTH0_DOMAIN"),
        client_id=env.get("AUTH0_CLIENT_ID"),
        client_secret=env.get("AUTH0_CLIENT_SECRET"),
        redirect_uri=env.get("APP_BASE_URL") + "/callback",
        authorization_params={"scope": "openid profile email"},
        secret=session_secret,
        state_store=CookieStore(session_secret, "_a0_session", 259200, StateData),  # 3 days
        transaction_store=CookieStore(session_secret, "_a0_tx", 300, TransactionData),  # 5 min
    )


@app.route("/")
async def home():
    user = await auth0().get_user({"request": request})

    head = "<!DOCTYPE html><title>Auth0 Python Sample</title>"

    if user:
        metadata = user.get("user_metadata", {}) or {}
        tipo_documento = metadata.get("tipo_documento", "")
        numero_documento = metadata.get("numero_documento", "")
        direccion = metadata.get("direccion", "")
        telefono = metadata.get("telefono", "")

        return f"""
            {head}
            <p>Sesión iniciada como {escape(user.get("email", ""))}</p>
            <h1>Perfil de usuario</h1>
            
            <h2>Actualizar Datos Personales</h2>
            <form method="POST" action="/update-profile" style="margin-bottom: 20px;">
                <label>1. Tipo de documento:</label><br>
                <input type="text" name="tipo_documento" value="{escape(tipo_documento)}" placeholder="Ej: CC, TI"><br><br>
                
                <label>2. Número de documento:</label><br>
                <input type="text" name="numero_documento" value="{escape(numero_documento)}" placeholder="Número de documento"><br><br>
                
                <label>3. Dirección:</label><br>
                <input type="text" name="direccion" value="{escape(direccion)}" placeholder="Dirección de residencia"><br><br>
                
                <label>4. Teléfono:</label><br>
                <input type="text" name="telefono" value="{escape(telefono)}" placeholder="Número telefónico"><br><br>
                
                <button type="submit">Guardar cambios</button>
            </form>

            <pre>{escape(json.dumps(user, indent=2))}</pre>
            <a href="/logout">Cerrar sesión</a>
        """

    return f"""
        {head}
        <a href="/login?screen_hint=signup">Signup</a>
        <a href="/login">Login</a>
    """


@app.route("/login")
async def login():
    url = await auth0().start_interactive_login(
        options=StartInteractiveLoginOptions(
            authorization_params=dict(request.args),
        ),
        store_options={"request": request},
    )
    return redirect(url)


@app.route("/callback")
async def callback():
    try:
        await auth0().complete_interactive_login(
            url=request.url, store_options={"request": request},
        )
        return redirect("/")
    except Exception:
        app.logger.exception("Callback error")
        return "Something went wrong. Check server logs for details.", 400


@app.route("/logout")
async def logout():
    url = await auth0().logout(
        options=LogoutOptions(return_to=env.get("APP_BASE_URL")),
        store_options={"request": request},
    )
    return redirect(url)


@app.route("/update-profile", methods=["POST"])
async def update_profile():
    user = await auth0().get_user({"request": request})
    if not user:
        return redirect("/login")

    tipo_documento = request.form.get("tipo_documento")
    numero_documento = request.form.get("numero_documento")
    direccion = request.form.get("direccion")
    telefono = request.form.get("telefono")

    domain = env.get("AUTH0_DOMAIN")
    client_id = env.get("AUTH0_CLIENT_ID")
    client_secret = env.get("AUTH0_CLIENT_SECRET")

    try:
        token_url = f"https://{domain}/oauth/token"
        token_payload = {
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": client_secret,
            "audience": f"https://{domain}/api/v2/"
        }
        
        token_res = requests.post(token_url, json=token_payload)
        
        if token_res.status_code == 200:
            access_token = token_res.json().get("access_token")
            user_id = user.get("sub")

            api_url = f"https://{domain}/api/v2/users/{user_id}"
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json"
            }
            body = {
                "user_metadata": {
                    "tipo_documento": tipo_documento,
                    "numero_documento": numero_documento,
                    "direccion": direccion,
                    "telefono": telefono
                }
            }
            
            res = requests.patch(api_url, json=body, headers=headers)
            print("RESPUESTA DE AUTH0:", res.status_code, res.text)
            
    except Exception as e:
        app.logger.error(f"Error actualizando user_metadata: {e}")

    return redirect("/")


if __name__ == "__main__":
    url = urlparse(env.get("APP_BASE_URL"))
    app.run(host=url.hostname, port=url.port or 5000)