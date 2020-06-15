import java.io.*;
import java.net.*;

public class Server {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		
		try {
			ServerSocket ser_socket = new ServerSocket(8889);
			Socket cli_socket = ser_socket.accept();
			
			recvfclient r = new recvfclient();
			r.setSocket(cli_socket);
			send2client s = new send2client();
			s.setSocket(cli_socket);
			
			r.start();
			s.start();
			
			ser_socket.close();
			
		}catch(IOException e){
			System.out.println(e);
		}
	}
	
}

class send2client extends Thread{
	
	private Socket cli_socket;
	
	public void run() {
		super.run();
		try {
			BufferedReader keyboard = new BufferedReader(new InputStreamReader(System.in));
			PrintWriter pw = new PrintWriter(cli_socket.getOutputStream());
			
			String line = null;
			while(true) {
				line = keyboard.readLine();
				pw.println(line);
				pw.flush();
				if(line.equals("exit")) {
					System.out.println("exit");
					cli_socket.close();
					System.exit(0);
				}
			}
		}catch(IOException e) {
			System.out.println(e);
		}
	}
	
	public void setSocket(Socket _socket) {
		cli_socket = _socket;
	}
}

class recvfclient extends Thread{
	
	private Socket cli_socket;
	
	public void setSocket(Socket _socket) {
		cli_socket = _socket;
		
	}
	
	public void run() {
		super.run();
		try {
			BufferedReader br = new BufferedReader(new InputStreamReader(cli_socket.getInputStream()));
			String msg = null;
			
			while(true) {
				msg = br.readLine();
				if(msg == null) {
					System.out.println("close");
					cli_socket.close();
					System.exit(0);
				}
				System.out.println(msg);
				if(msg == null) {
					System.out.println("close");
					cli_socket.close();
					System.exit(0);
				}
			}
			
		}catch(IOException e) {
			System.out.println(e);
		}
	}
	
}
