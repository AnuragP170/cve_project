# import pandas as pd
# import mysql.connector
# from mysql.connector import Error
#
# def read_excel(file_path):
#     # Read the Excel file
#     df = pd.read_excel(file_path)
#     # Replace NaN values with a default value, for example, an empty string or None
#     df = df.fillna(value={
#         'CVE ID': '',
#         'Description': '',
#         'Published Date': None,
#         'Last Modified Date': None,
#         'Affected Platform': '',
#         'CVSS Version': '',
#         'Base Score': 0,
#         'Base Severity': '',
#         'References': '',
#         'CWE': '',
#         'assigner': ''
#     })
#     return df
#
# def connect_to_database():
#     try:
#         connection = mysql.connector.connect(
#             host='localhost',
#             database='cve_database',
#             user='admin2',
#             password='admin123'
#         )
#         if connection.is_connected():
#             return connection
#     except Error as e:
#         print(f"Error: {e}")
#         return None
#
# def insert_data_to_database(connection, df):
#     cursor = connection.cursor()
#     for index, row in df.iterrows():
#         sql_insert_query = """
#         INSERT INTO entire_cve_list (cve_id, description, published_date, last_modified_date, affected_platform, cvss_version, base_score, base_severity, references_list, cwe, assigner)
#         VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
#         """
#         cursor.execute(sql_insert_query, (
#             row['CVE ID'],
#             row['Description'],
#             row['Published Date'],
#             row['Last Modified Date'],
#             row['Affected Platform'],
#             row['CVSS Version'],
#             row['Base Score'],
#             row['Base Severity'],
#             row['References'],
#             row['CWE'],
#             row['assigner']
#         ))
#     connection.commit()
#     cursor.close()
#
# def main():
#     excel_file_path = 'processed_cve_data.xlsx'  # Update this to the path of your Excel file
#     df = read_excel(excel_file_path)
#     connection = connect_to_database()
#     if connection:
#         insert_data_to_database(connection, df)
#         connection.close()
#
# if __name__ == "__main__":
#     main()
import pandas as pd
from sqlalchemy import create_engine
import logging
import pymysql

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database configuration
db_user = 'admin2'
db_password = 'admin123'
db_host = 'localhost'
db_port = '3306'
db_name = 'cve_database'
db_table = 'entire_cve_list'

# Path to your Excel file
excel_file_path = 'processed_cve_data.xlsx'

try:
    # Create a connection to the database
    engine = create_engine(f'mysql+pymysql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}')
    logging.info("Database connection established.")

    # Read the Excel file
    df = pd.read_excel(excel_file_path, engine='openpyxl')
    logging.info("Excel file read successfully.")

    # Rename DataFrame columns to match the database table columns
    df.rename(columns={
        'CVE ID': 'cve_id',
        'Description': 'description',
        'Published Date': 'published_date',
        'Last Modified Date': 'last_modified_date',
        'Affected Platform': 'affected_platform',
        'CVSS Version': 'cvss_version',
        'Base Score': 'base_score',
        'Base Severity': 'base_severity',
        'References': 'references_list',
        'CWE': 'cwe',
        'assigner': 'assigner'
    }, inplace=True)

    # Ensure date columns are in datetime format
    df['published_date'] = pd.to_datetime(df['published_date'], errors='coerce')
    df['last_modified_date'] = pd.to_datetime(df['last_modified_date'], errors='coerce')

    # Insert data into the database
    df.to_sql(db_table, con=engine, if_exists='append', index=False)
    logging.info("Data has been successfully inserted into the database.")

except Exception as e:
    logging.error(f"An error occurred: {e}")
