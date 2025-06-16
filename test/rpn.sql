DROP TABLE IF EXISTS Payees;
DROP TABLE IF EXISTS Issues;
DROP TABLE IF EXISTS Lapses;
-- ref=hmac256(blindMsg, rsaPubKey), sess_stat (open/completed/expired), pay_stat (paid/unpaid/no_payment_required), prod (product_id), tx=stripe.checkout.session, ts=now
CREATE TABLE IF NOT EXISTS Payees (ref VARCHAR(64) PRIMARY KEY, sess_stat TEXT, pay_stat TEXT, prod TEXT, tx JSON, ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL);
-- ref=sha256(unblindedSig), n=count(tokens), ts=now
CREATE TABLE IF NOT EXISTS Issues (ref VARCHAR(64) PRIMARY KEY, n INTEGER DEFAULT 1, ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL);
-- id=stripe.session.id, tx=stripe.session, reason=for-failure, ts=now
CREATE TABLE IF NOT EXISTS Lapses (id TEXT PRIMARY KEY, tx JSON, reason TEXT, ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL);
