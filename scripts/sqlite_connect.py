'''
try:
   
    # Connect to DB and create a cursor
    connection = sqlite3.connect('pentester.db')
    cursor = connection.cursor()
    cursor.execute('' CREATE TABLE ports
         (FIND INT PRIMARY KEY     NOT NULL,
         FNAME           TEXT    NOT NULL,
         COST            INT     NOT NULL,
         WEIGHT        INT);
         '')
    connection.execute("INSERT INTO hotel VALUES (1, 'cakes',800,10 )")
    print('DB Init')
 
    # Write a query and execute it with cursor
    query = 'select sqlite_version();'
    cursor.execute(query)
 
    # Fetch and output result
    result = cursor.fetchall()
    print('SQLite Version is {}'.format(result))
 
    # Close the cursor
    cursor.close()
 
# Handle errors
except sqlite3.Error as error:
    print('Error occurred - ', error)
 
# Close DB Connection irrespective of success
# or failure
finally:
   
    if sqliteConnection:
        sqliteConnection.close()
        print('SQLite Connection closed')
'''
