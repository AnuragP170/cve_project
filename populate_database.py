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
# import pandas as pd
# from sqlalchemy import create_engine
# import logging
# import pymysql
# import urllib.parse

# # Setup logging
# logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# # Database configuration
# # db_user = 'admin2'
# # db_password = 'admin123'
# # db_host = 'localhost'
# # db_port = '3306'
# # db_name = 'cve_database'
# # db_table = 'entire_cve_list'

# db_user = 'team27'
# db_password = 'redacted'
# db_host = 'redacted'
# db_port = '3306'
# db_name = 'Mitigation'
# db_table = 'entire_cve_list'
# db_password_encoded = urllib.parse.quote_plus(db_password)
# # Path to your Excel file
# excel_file_path = 'processed_cve_data.xlsx'

# try:
#     # Create a connection to the database
#     engine = create_engine(f'mysql+pymysql://{db_user}:{db_password_encoded}@{db_host}:{db_port}/{db_name}')
#     logging.info("Database connection established.")

#     # Read the Excel file
#     df = pd.read_excel(excel_file_path, engine='openpyxl')
#     logging.info("Excel file read successfully.")

#     # Rename DataFrame columns to match the database table columns
#     df.rename(columns={
#         'CVE ID': 'CVE_ID',
#         'Description': 'Description',
#         'Published Date': 'Published_Date',
#         'Last Modified Date': 'Last_Modified_Date',
#         'Affected Platform': 'Affected_Platform',
#         'CVSS Version': 'CVSS_Version',
#         'Base Score': 'Base_Score',
#         'Base Severity': 'Base_Severity',
#         'References': 'References',
#         'CWE': 'CWE',
#         'assigner': 'assigner'
#     }, inplace=True)

#     # Ensure date columns are in datetime format
#     df['Published_Date'] = pd.to_datetime(df['Published_Date'], errors='coerce')
#     df['Last_Modified_Date'] = pd.to_datetime(df['Last_Modified_Date'], errors='coerce')

#     # Insert data into the database
#     df.to_sql(db_table, con=engine, if_exists='append', index=False)
#     logging.info("Data has been successfully inserted into the database.")

# except Exception as e:
#     logging.error(f"An error occurred: {e}")
import pandas as pd
from sqlalchemy import create_engine, text
import logging
import pymysql
import urllib.parse

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Database credentials
db_config = {
    'user': 'team27',
    'password': 'T3@m27!',
    'host': '54.79.198.148',
    'port': 3306,
    'database': 'Mitigation',
    'table': 'cve_data'
}
db_password_encoded = urllib.parse.quote_plus(db_config['password'])

# Function to create the database connection
def create_connection(use_db=False):
    try:
        if use_db:
            conn = pymysql.connect(user=db_config['user'], password=db_config['password'], host=db_config['host'], port=db_config['port'], database=db_config['database'])
        else:
            conn = pymysql.connect(user=db_config['user'], password=db_config['password'], host=db_config['host'], port=db_config['port'])
        logging.info("Database connection successful")
        return conn
    except Exception as e:
        logging.error(f"Error connecting to database: {e}")
        return None

# Function to check if a table exists
def table_exists(conn, db_name, table_name):
    try:
        use_db_query = f"USE {db_name};"
        with conn.cursor() as cursor:
            cursor.execute(use_db_query)
            cursor.execute(f"SHOW TABLES LIKE '{table_name}';")
            result = cursor.fetchone()
            logging.info(f"Table exists check result: {result}")
            return result is not None
    except Exception as e:
        logging.error(f"Error checking if table exists: {e}")
        return False

# Function to create the CVE table based on Excel columns
def create_cve_table(conn, db_name, table_name, columns):
    use_db_query = f"USE {db_name};"
    
    create_table_query = f"CREATE TABLE IF NOT EXISTS `{table_name}` ("
    column_definitions = ["`entry_id` INT AUTO_INCREMENT PRIMARY KEY"]
    
    for column_name in columns:
        sql_type = 'TEXT'  # Default to TEXT for simplicity
        if 'date' in column_name.lower():
            sql_type = 'DATETIME'
        
        if column_name == 'CVE ID':
            column_definitions.append(f"`{column_name.replace(' ', '_')}` VARCHAR(255) NULL")
        else:
            column_definitions.append(f"`{column_name.replace(' ', '_')}` {sql_type} NULL")
    
    create_table_query += ", ".join(column_definitions) + ", UNIQUE (`CVE_ID`(255)));"

    with conn.cursor() as cursor:
        cursor.execute(use_db_query)
        cursor.execute(create_table_query)
        conn.commit()
        logging.info(f"Table '{table_name}' created or already exists")

# Function to insert data into the CVE table using SQLAlchemy for bulk insertion
def insert_cve_data(engine, cve_data, table_name):
    try:
        # Standardize column names and remove entry_id if present
        cve_data.columns = [col.replace(' ', '_') for col in cve_data.columns]
        if 'entry_id' in cve_data.columns:
            cve_data.drop(columns=['entry_id'], inplace=True)

        # Replace NaN with None
        cve_data = cve_data.where(pd.notnull(cve_data), None)
        
        # Insert data into the database
        cve_data.to_sql(table_name, con=engine, if_exists='append', index=False)
        
        logging.info("Data has been successfully inserted into the database.")
    except Exception as e:
        logging.error(f"An error occurred while inserting data into the database: {e}")

# Function to count and print the number of entries in the table
def count_entries(engine, table_name):
    count_query = f"SELECT COUNT(*) FROM `{table_name}`;"
    try:
        with engine.connect() as conn:
            result = conn.execute(text(count_query))
            count = result.scalar()
            logging.info(f"Total number of entries in '{table_name}': {count}")
    except Exception as e:
        logging.error(f"Error counting entries: {e}")

# Main function to execute the process
def main():
    # Path to the CVE Excel file
    excel_file_path = 'processed_cve_data.xlsx'

    # Load the CVE data from Excel
    cve_data = pd.read_excel(excel_file_path)

    # Convert date columns to datetime with error handling
    for col in cve_data.columns:
        if 'date' in col.lower():
            cve_data[col] = pd.to_datetime(cve_data[col], errors='coerce')

    # Get column names
    columns = cve_data.columns

    # Print column names for debugging
    logging.info(f"Column names: {columns}")

    # Create the initial database connection using pymysql for dynamic table handling
    conn = create_connection(use_db=True)
    if conn:
        db_name = db_config['database']
        table_name = db_config['table']

        # Create the CVE table if it doesn't exist
        if not table_exists(conn, db_name, table_name):
            create_cve_table(conn, db_name, table_name, columns)
        conn.close()

    # Create SQLAlchemy engine for bulk insertion
    engine = create_engine(f'mysql+pymysql://{db_config["user"]}:{db_password_encoded}@{db_config["host"]}:{db_config["port"]}/{db_name}')
    logging.info("SQLAlchemy engine created successfully.")

    # Insert the CVE data using SQLAlchemy for bulk insertion
    insert_cve_data(engine, cve_data, table_name)

    # Count and print the number of entries
    count_entries(engine, table_name)

if __name__ == '__main__':
    main()
