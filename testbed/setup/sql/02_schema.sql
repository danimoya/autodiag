SET FEEDBACK OFF
ALTER SESSION SET CONTAINER = FREEPDB1;
ALTER SESSION SET CURRENT_SCHEMA = autodiag_test;

CREATE TABLE customers (
    customer_id NUMBER       PRIMARY KEY,
    name        VARCHAR2(60) NOT NULL,
    region      VARCHAR2(20) NOT NULL,
    created     DATE         NOT NULL,
    status      VARCHAR2(10) NOT NULL
);
CREATE TABLE orders (
    order_id    NUMBER        PRIMARY KEY,
    customer_id NUMBER        NOT NULL,
    order_date  DATE          NOT NULL,
    status      VARCHAR2(10)  NOT NULL,
    amount      NUMBER(12, 2) NOT NULL,
    CONSTRAINT fk_orders_customer FOREIGN KEY (customer_id) REFERENCES customers
);
CREATE TABLE order_items (
    item_id  NUMBER        PRIMARY KEY,
    order_id NUMBER        NOT NULL,
    product  VARCHAR2(40)  NOT NULL,
    qty      NUMBER        NOT NULL,
    price    NUMBER(10, 2) NOT NULL,
    CONSTRAINT fk_items_order FOREIGN KEY (order_id) REFERENCES orders
);
CREATE INDEX idx_orders_customer ON orders (customer_id);
CREATE INDEX idx_items_order     ON order_items (order_id);
-- Two rows updated in opposite order by pkg_orders.deadlock_a / deadlock_b
CREATE TABLE lock_demo (id NUMBER PRIMARY KEY, val VARCHAR2(20));
