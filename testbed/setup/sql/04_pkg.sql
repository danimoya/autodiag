SET FEEDBACK OFF
ALTER SESSION SET CONTAINER = FREEPDB1;

CREATE OR REPLACE PACKAGE autodiag_test.pkg_orders AS
    FUNCTION  report_customer(p_customer_id IN NUMBER) RETURN NUMBER;
    PROCEDURE run_workload(p_iterations IN PLS_INTEGER DEFAULT 200);
    PROCEDURE slow_toggle(p_slow IN BOOLEAN);
    PROCEDURE deadlock_a;
    PROCEDURE deadlock_b;
    PROCEDURE busy_loop(p_seconds IN PLS_INTEGER DEFAULT 60);
    PROCEDURE slow_scan(p_seconds IN PLS_INTEGER DEFAULT 60);
END pkg_orders;
/
CREATE OR REPLACE PACKAGE BODY autodiag_test.pkg_orders AS

    FUNCTION report_customer(p_customer_id IN NUMBER) RETURN NUMBER IS
        l_total NUMBER;
    BEGIN
        SELECT /* autodiag_report_customer */ SUM(oi.qty * oi.price)
          INTO l_total
          FROM orders o
          JOIN order_items oi ON oi.order_id = o.order_id
         WHERE o.customer_id = p_customer_id;
        RETURN NVL(l_total, 0);
    END report_customer;

    PROCEDURE run_workload(p_iterations IN PLS_INTEGER DEFAULT 200) IS
        l_dummy NUMBER;
    BEGIN
        FOR i IN 1 .. p_iterations LOOP
            l_dummy := report_customer(MOD(i * 37, 100000) + 1);
        END LOOP;
    END run_workload;

    -- Makes the customer index invisible so report_customer must full-scan ORDERS.
    PROCEDURE slow_toggle(p_slow IN BOOLEAN) IS
    BEGIN
        IF p_slow THEN
            EXECUTE IMMEDIATE 'ALTER INDEX idx_orders_customer INVISIBLE';
        ELSE
            EXECUTE IMMEDIATE 'ALTER INDEX idx_orders_customer VISIBLE';
        END IF;
    END slow_toggle;

    PROCEDURE deadlock_a IS
    BEGIN
        UPDATE lock_demo SET val = 'a1' WHERE id = 1;
        DBMS_SESSION.SLEEP(3);
        UPDATE lock_demo SET val = 'a2' WHERE id = 2;
        COMMIT;
    END deadlock_a;

    PROCEDURE deadlock_b IS
    BEGIN
        UPDATE lock_demo SET val = 'b2' WHERE id = 2;
        DBMS_SESSION.SLEEP(3);
        UPDATE lock_demo SET val = 'b1' WHERE id = 1;
        COMMIT;
    END deadlock_b;

    -- Keeps a foreground process busy executing SQL (target for a SIGSEGV -> ORA-7445).
    PROCEDURE busy_loop(p_seconds IN PLS_INTEGER DEFAULT 60) IS
        l_end DATE := SYSDATE + p_seconds / 86400;
        l_n   NUMBER;
    BEGIN
        WHILE SYSDATE < l_end LOOP
            SELECT COUNT(*) INTO l_n FROM customers WHERE customer_id BETWEEN 1 AND 100;
        END LOOP;
    END busy_loop;

    -- Long consistent read over ORDERS, row by row (used to provoke ORA-1555).
    PROCEDURE slow_scan(p_seconds IN PLS_INTEGER DEFAULT 60) IS
        l_end DATE := SYSDATE + p_seconds / 86400;
        l_sum NUMBER := 0;
    BEGIN
        FOR r IN (SELECT amount FROM orders ORDER BY order_id) LOOP
            l_sum := l_sum + r.amount;
            DBMS_SESSION.SLEEP(0.002);
            EXIT WHEN SYSDATE > l_end;
        END LOOP;
    END slow_scan;
END pkg_orders;
/
