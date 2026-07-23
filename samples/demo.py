import os


def run_report(user_name: str) -> None:
    query = f"SELECT * FROM reports WHERE owner = '{user_name}'"
    os.system("report-tool --query " + query)

