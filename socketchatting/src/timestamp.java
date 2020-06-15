import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Calendar;

public class timestamp {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		SimpleDateFormat format = new SimpleDateFormat("[yyyy/MM/dd hh:mm:ss]");
		Calendar cal = Calendar.getInstance();
		String today = format.format(cal.getTime());
		System.out.println(today);

	}

}
