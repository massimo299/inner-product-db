### **Secure Database**

This project includes a set of programs that can be used to encrypt tables (consisting of rows and columns) 
so that the owner of the table can create tokens to allow third party users to perform queries on the 
encrypted tables. 

The current release allows very simple queries in which it is possible to read one specific column of all 
rows that satisfy a certain predicate. Only equality predicates are currently supported. 
These roughly correspond to SQL queries of the following form:

-> select col5 from table where col1='AA' and col2='BB' and col4='DD' <-

that show the fifth column of all rows in which the first column is 'AA', the second is 'BB' and the fourth
is 'DD'.  

The following is a typical workflow:

1. **Generate keys:**

	run command **GenKey** \<num_col\> \<key_file\>
	* \<num_col\>:  number of columns in the table we intend to encrypt;
	* \<key_file\>: the name of the file in which the key will be saved;

2. **Encrypt rows:**

	run command **EncRow** \<key_file\> \<table_name\> \<enctable_name\> \<noise\>
	* \<key_file\>:  name of the file that contains the master key to be used for the encryption;
	* \<table_name\>: file name of the table;
	* \<enctable_name\>: file name of the encrypted table;
	* \<noise\>: the noise parameter;


3. **Token generation:**

	run command **GenToken** \<key_file\> \<query_name\> \<noise\>
	* \<key_file\>: name of the file that contains the master key to be used for the token generation;
	* \<query_name\>: the name of the file that contains the query;
	* \<noise\>: the noise parameter;

4. **Token execution:**

	run command **ApplyToken** \<query_name\> \<enctable_name\>
	* \<query_name\>: the name of the file to be used to get the different tokens;
	* \<enctable_name\>: file name of the encrypted table.

#### **File formats**
* **Table format:**

	A table with m rows and n columns has to be structured as follows:

	row1cell1#row1cell2#row1cell3#....#row1celln  
	rowmcell1#rowncell2#rowncell3#....#rowmcelln

	Elements of the same row are separated by '#' character.  
	Examples are in files 'row_120'(1 row, 120 cells) and 'rows_8_40'(40 rows, 8 cells).

* **Query format:**

	A query for a n columns database with s select to perform has to be structured as follows:

	select1#select2#...#selects  
	where1  
	where2  

	where4  
	...  
	wheren  

	The new line character is considered like there's not a where condition for that cell.

* **Noise parameter:**

	A random parameter is generated during encryption (one per each row) and query generation (one per each select parameter of the query) phase to add noise to the query resulsts. If the two random parameters match, the query returns that row even if the where parameters aren't satisfied.
