### **Secure Database**

This project includes a set of programs that can be used to encrypt tables (consisting of rows and columns) so that the owner of the data can create tokens to allow third party users to perform query on the encrypted tables and access only the informations that the token permitts them.

1. **Generate keys:**

	run command **GenKey** <num_col> <key_name>
	* <num_col> is the number of column that the created key will be able to encrypt;
	* <key_name> represents the name of the file in which the key will be saved;
	* the created master key will be written in Keys/<key_name>.

2. **Encrypt rows:**

	run command **EncRow** <key_name> <rows_name> <rand_lim>
	* <key_name> is the name of the master, key needed for the encryption;
	* <rows_name> file name of the table;
	* <rand_lim> this is the maximum limit of the noise parameter generation (minimum is 1);
	* the encrypted table will be written in EncRows/<rows_name>_enc_msgs;
	* every ciphertext (one per each row) will be stored in Ciphertexts/<rows_name>_enc_ct0,<rows_name>_enc_ct1,....,<rows_name>_enc_ctn (where n is the number of rows).

2. **Query generation and execution:**
	run command **QueGenExe** <key_name> <query_name> <db_name> <rand_lim>
	* <key_name> is the name of the master key, needed for the decryption;
	* <query_name> indicates the file that contains the query;
	* <db_name> file name of the encrypted table;
	* <rand_lim> this is the maximum limit of the noise parameter generation (minimum is 1);
	* the decryption results will be printed on the standard output.

#### **Additional informations**
* **Table structure:**

	A table with m rows and n columns has to be structured as follows:

	row1cell1#row1cell2#row1cell3#....#row1celln  
	rowmcell1#rowncell2#rowncell3#....#rowmcelln

	In which every element is separated by a '#' character.
	Example are in files 'row_120'(1 row, 120 cells) and 'rows_8_40'(40 rows, 8 cells).
* **Query structure:**

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
