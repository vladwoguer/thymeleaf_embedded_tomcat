package example.thymeleaf;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.InvalidParameterException;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.startup.Tomcat;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templatemode.TemplateMode;
import org.thymeleaf.templateresolver.ClassLoaderTemplateResolver;

/**
 * Servlet + Thymeleaf!
 *
 */
public class App {
	public static List<User> users = new LinkedList<User>();

	public static HashMap<String, LocalDateTime> sessions = new HashMap<String, LocalDateTime>();

	public static void main(String[] args) throws LifecycleException {

		users.add(new User("admin", "12345", "admin@admin.com"));

		int port = 8080;
		Tomcat tomcat = new Tomcat();
		tomcat.setBaseDir("temp");
		tomcat.setPort(port);

		String docBase = new File(".").getAbsolutePath();
		String contextPath = "/";
		org.apache.catalina.Context context = tomcat.addContext(contextPath, docBase);

		addServlet(tomcat, context, login(), "login", "/", contextPath);
		addServlet(tomcat, context, login(), "login2", "/login", contextPath);
		addServlet(tomcat, context, newUser(), "newuser", "/new", contextPath);
		addServlet(tomcat, context, users(), "users", "/users", contextPath);

		tomcat.start();
		tomcat.getServer().await();

	}

	public static HttpServlet users() {
		return new HttpServlet() {

			@Override
			protected void doGet(HttpServletRequest req, HttpServletResponse resp)
					throws ServletException, IOException {
				PrintWriter writer = resp.getWriter();
				
				if(!authorized(req.getCookies())) {
					writer.println(template("unathorized.html", getContext()));
					return;
				}

				Context context = getContext();
				
				context.setVariable("users", users);
				writer.println(template("users.html", context));
			}
		};
	}

	public static HttpServlet newUser() {
		return new HttpServlet() {
			@Override
			protected void doPost(HttpServletRequest req, HttpServletResponse resp)
					throws ServletException, IOException {
				PrintWriter writer = resp.getWriter();
				if(!authorized(req.getCookies())) {
					writer.println(template("unathorized.html", getContext()));
					return;
				}

				String username = req.getParameter("username");
				String password = req.getParameter("password");
				String email = req.getParameter("email");

				if (isNullOrEmpty(username) || isNullOrEmpty(password) || isNullOrEmpty(email)) {
					writer.println(template("invalid_data.html", getContext()));
				} else {
					try {
						addUser(username, password, email);
						resp.sendRedirect("/users");
					} catch (InvalidParameterException e) {
						writer.println(template("invalid_data.html", getContext()));
					}

				}

			}

			@Override
			protected void doGet(HttpServletRequest req, HttpServletResponse resp)
					throws ServletException, IOException {
				PrintWriter writer = resp.getWriter();
				
				if(!authorized(req.getCookies())) {
					writer.println(template("unathorized.html", getContext()));
					return;
				}

				writer.println(template("new_user.html", getContext()));
			}
		};
	}

	protected static boolean authorized(Cookie[] cookies) {
		cookies = cookies == null ? new Cookie[0] : cookies;
		for (int i = 0; i < cookies.length; i++) {
			if(cookies[i].getName().equals("session")) {
				LocalDateTime session = sessions.get(cookies[i].getValue());
				if(session != null && session.isAfter(LocalDateTime.now())) {
					return true;
				}
			}
		}
		return false;
	}

	protected static boolean isNullOrEmpty(String str) {
		return str == null || str.isEmpty();
	}

	public static HttpServlet login() {
		return new HttpServlet() {
			@Override
			protected void doGet(HttpServletRequest req, HttpServletResponse resp)
					throws ServletException, IOException {
				PrintWriter writer = resp.getWriter();

				writer.println(template("login.html", getContext()));

			}

			@Override
			protected void doPost(HttpServletRequest req, HttpServletResponse resp)
					throws ServletException, IOException {
				PrintWriter writer = resp.getWriter();
				Context ct = getContext();
				String username = req.getParameter("username");
				String password = req.getParameter("password");

				if (authenticate(username, password)) {

					ct.setVariable("username", username);
					ct.setVariable("date", LocalDateTime.now());

					String sessionID = UUID.randomUUID().toString().replaceAll("-", "");
					sessions.put(sessionID, LocalDateTime.now().plusMinutes(15));
					Cookie userCookie = new Cookie("session", sessionID);
					userCookie.setMaxAge(15 * 60);
					resp.addCookie(userCookie);
					writer.println(template("welcome.html", ct));
				} else {
					writer.println(template("unathorized.html", ct));
				}

			}

			private boolean authenticate(String username, String password) {
				Map<String, String> users = getUsers();
				if (notNull(username) && notNull(password)) {
					return notNull(users.get(username)) && users.get(username).equals(password);
				}
				return false;
			}

			private boolean notNull(String str) {
				return str != null;
			}
		};

	}

	public static void addServlet(Tomcat tomcat, org.apache.catalina.Context context, HttpServlet servlet,
			String servletName, String urlPattern, String contextPath) {

		tomcat.addServlet(contextPath, servletName, servlet);
		context.addServletMappingDecoded(urlPattern, servletName);
	}

	public static Map<String, String> getUsers() {
		Map<String, String> users = new HashMap<String, String>();

		for (User user : App.users) {
			users.put(user.getUsername(), user.getPassword());
		}
		return users;
	}

	public static void changePassword(String username, String password) {
		for (User user : App.users) {
			if (user.getUsername().equals(username)) {
				user.setPassword(password);
			}
		}
	}

	public static void addUser(String username, String password, String email) {
		String user = getUsers().get(username);
		if (user != null && user.equals(password)) {
			throw new InvalidParameterException("User already exists");
		} else {
			users.add(new User(username, password, email));
		}
	}

	public static Context getContext() {
		return new Context();
	}

	public static String template(String template, Context ct) {
		TemplateEngine templateEngine = new TemplateEngine();
		ClassLoaderTemplateResolver resolver = new ClassLoaderTemplateResolver();
		resolver.setPrefix("/templates/");
		resolver.setSuffix(".html");
		resolver.setCharacterEncoding("UTF-8");
		resolver.setTemplateMode(TemplateMode.HTML); // HTML5 option was
														// deprecated in 3.0.0
		templateEngine.setTemplateResolver(resolver);

		return templateEngine.process(template, ct);
	}
}
