SET FEEDBACK OFF
ALTER SESSION SET CONTAINER = FREEPDB1;
ALTER SESSION SET CURRENT_SCHEMA = autodiag_test;

INSERT INTO customers (customer_id, name, region, created, status)
SELECT level,
       'Customer ' || level,
       CASE MOD(level, 4) WHEN 0 THEN 'EMEA' WHEN 1 THEN 'AMER' WHEN 2 THEN 'APAC' ELSE 'LATAM' END,
       SYSDATE - MOD(level, 365),
       CASE WHEN MOD(level, 50) = 0 THEN 'CLOSED' ELSE 'ACTIVE' END
  FROM dual CONNECT BY level <= 100000;
COMMIT;

INSERT INTO orders (order_id, customer_id, order_date, status, amount)
SELECT level,
       MOD(level * 7, 100000) + 1,
       SYSDATE - MOD(level, 730),
       CASE MOD(level, 5) WHEN 0 THEN 'SHIPPED' WHEN 1 THEN 'OPEN' WHEN 2 THEN 'PAID'
                          WHEN 3 THEN 'CANCELLED' ELSE 'RETURNED' END,
       ROUND(DBMS_RANDOM.VALUE(10, 5000), 2)
  FROM dual CONNECT BY level <= 100000;
COMMIT;

INSERT INTO order_items (item_id, order_id, product, qty, price)
SELECT level,
       MOD(level, 100000) + 1,
       'Product ' || MOD(level, 500),
       MOD(level, 9) + 1,
       ROUND(DBMS_RANDOM.VALUE(1, 500), 2)
  FROM dual CONNECT BY level <= 300000;
COMMIT;

INSERT INTO lock_demo VALUES (1, 'a');
INSERT INTO lock_demo VALUES (2, 'b');
COMMIT;

EXEC DBMS_STATS.GATHER_SCHEMA_STATS('AUTODIAG_TEST')
