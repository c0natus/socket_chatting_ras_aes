import java.io.*;
import java.net.*;

public class Client {

	public static void main(String[] args) {
		// TODO Auto-generated method stub
		try {
			Socket cli_socket = new Socket("127.0.0.1",8889);
			
			recvfserver r = new recvfserver();
			r.setSocket(cli_socket);
			send2server s = new send2server();
			s.setSocket(cli_socket);
			
			r.start();
			s.start();			
	
		} catch(IOException e) {
			System.out.println(e);
		}

	}

}

class send2server extends Thread{
	
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

class recvfserver extends Thread{
	
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
				System.out.println(msg);
				if(msg==null) {
					System.out.println("exit");
					cli_socket.close();
					System.exit(0);
				}
			}
			
		}catch(IOException e) {
			System.out.println(e);
		}
	}
	
}

