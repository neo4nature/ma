# MA50 — Auth/FID route split

Changes:
- extracted register/login/logout/FID routes into `routes/auth.py`
- added `services/auth_service.py` thin wrappers
- left legacy implementations in `app.py` unchanged to preserve behavior

Intent:
- continue breaking down the Flask monolith safely
- keep runtime behavior stable while reducing routing concentration
