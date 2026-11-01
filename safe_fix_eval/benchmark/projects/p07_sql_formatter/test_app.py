# Toy project: splits and formats SQL with sqlparse.
import sqlparse


def split_statements(sql):
    return [s.strip() for s in sqlparse.split(sql) if s.strip()]


def test_split_two_statements():
    assert split_statements("select 1; select 2;") == ["select 1;", "select 2;"]


def test_keywords_uppercased():
    assert sqlparse.format("select a from t", keyword_case="upper") == "SELECT a FROM t"
