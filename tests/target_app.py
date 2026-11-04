"""A small, deliberately-flawed Flask app used ONLY as a local test target
for cdmcp. It is not exposed to the network beyond localhost and exists
purely so the scanner has something realistic to find:

- a fake "soft 404" catch-all that returns 200 for anything unknown
  (to exercise the noise filter)
- a few "real" hidden/sensitive paths the scanner should surface
- Express-like fingerprint signals (X-Powered-By header + a session cookie)

Run: python tests/target_app.py
Then point cdmcp at http://127.0.0.1:5055/ with scope set to 127.0.0.1.
"""

from flask import Flask, Response, make_response

app = Flask(__name__)

REAL_PATHS = {
    "/": "<html><body><h1>Widget Co</h1><p>Welcome to our totally normal site.</p></body></html>",
    "/.env": "DB_PASSWORD=supersecret\nAPI_KEY=abcdef123456\n",
    "/.git/HEAD": "ref: refs/heads/main\n",
    "/backup.sql": "-- mysqldump backup\nINSERT INTO users VALUES (1,'admin','hash');\n",
    "/admin": "<html><body><h1>Admin Panel</h1><form>...login...</form></body></html>",
    "/login": "<html><body><h1>Login</h1><form>...</form></body></html>",
    "/api/health": '{"status": "ok"}',
    "/robots.txt": "User-agent: *\nDisallow: /admin\n",
}


@app.after_request
def add_stack_signals(resp: Response) -> Response:
    resp.headers["X-Powered-By"] = "Express"
    resp.set_cookie("connect.sid", "s%3Afaketestsessionid")
    return resp


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def catch_all(path: str):
    full_path = "/" + path
    if full_path in REAL_PATHS:
        content_type = "application/json" if full_path.endswith("health") else "text/html"
        return Response(REAL_PATHS[full_path], status=200, content_type=content_type)

    # soft 404: looks like a normal 200 page instead of a real 404 --
    # this is exactly the noise the filter needs to learn and drop.
    body = (
        "<html><body><h1>Oops! Nothing here</h1>"
        "<p>The page you requested could not be located on this server. "
        "Please check the URL and try again, or head back to our homepage.</p>"
        "</body></html>"
    )
    return make_response(body, 200)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5055)
