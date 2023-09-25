import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

public class database {

    public void createTable(Connection conn) {
        String tableName = "characters";

        try (Statement stmt = conn.createStatement()) {

            String createTableSql = "CREATE TABLE " + tableName + " (" +
                    "characterid INTEGER PRIMARY KEY, " +
                    "weapon INT NOT NULL" +
                    ");";

            stmt.executeUpdate(createTableSql);
            System.out.println("Table is created");

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }

    public static void main(String[] args) {
        database db = new database();

        System.out.println("Enter the name of the database");
        String dbName = "myDatabase.db"; // Change this to your desired database name
        String url = "jdbc:sqlite:" + dbName;

        try (Connection conn = DriverManager.getConnection(url)) {
            System.out.println("Connection to SQLite has been established.");

            db.createTable(conn);

        } catch (SQLException e) {
            System.out.println(e.getMessage());
        }
    }
}
