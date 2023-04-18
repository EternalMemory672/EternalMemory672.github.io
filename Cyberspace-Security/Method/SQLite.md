# 创建数据库
```
sqlite3 dbname.db
.open dbname.db
```
# 创建数据表
```sql
CREATE TABLE database_name.table_name(
   column1 datatype  PRIMARY KEY(one or more columns),
   column2 datatype,
   column3 datatype,
   .....
   columnN datatype,
);
```
# 删除数据表
```sql
DROP TABLE database_name.table_name;
```
# 修改数据表
```sql
ALTER TABLE database_name.table_name RENAME TO new_table_name;
```
# 插入数据
```sql
INSERT INTO TABLE_NAME [(column1, column2, column3,...columnN)]  
VALUES (value1, value2, value3,...valueN);
```
# 查询数据
```sql
.header on
.mode column
SELECT column1, column2, columnN FROM table_name;
```
# 删除数据
```sql
DELETE FROM table_name
WHERE [condition];
```
# 修改数据
```sql
UPDATE table_name
SET column1 = value1, column2 = value2...., columnN = valueN
WHERE [condition];
```