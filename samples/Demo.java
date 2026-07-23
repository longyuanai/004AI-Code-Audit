package samples;

import java.sql.ResultSet;
import java.sql.Statement;

public class Demo {
    public ResultSet findReport(Statement statement, String owner) throws Exception {
        return statement.executeQuery(
            "SELECT * FROM reports WHERE owner = '" + owner + "'"
        );
    }
}

