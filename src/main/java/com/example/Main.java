package com.example;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.authentication.encoding.BasePasswordEncoder;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.Map;


@Controller
@SpringBootApplication
public class Main {
/*
	@Value("${spring.datasource.url}")
	private String dbUrl;

	@Autowired
	private DataSource dataSource;
	//private UserRepository userRepository;
*/
	public static void main(String[] args) throws Exception {
		SpringApplication.run(Main.class, args);
	}

	@RequestMapping({"/","/login"})
	String login() {
		return "login";
	}


/*
	@EnableWebSecurity
	public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
			.authorizeRequests()
			.antMatchers("/", "/login").permitAll()
			.antMatchers("/**").hasAnyRole("USER","ADMIN")
			.antMatchers("/Account/**").hasAnyRole("USER","ADMIN")
			.and()
			.formLogin()
			.loginPage("/login");
			http.formLogin()
			.defaultSuccessUrl("/Home", true)
			.and().logout().logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
			.logoutSuccessUrl("/")
			.deleteCookies("JSESSIONID")
			.invalidateHttpSession(true).permitAll();
		}

		@Autowired
		public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
			auth
			.inMemoryAuthentication()
			.withUser("user").password("pass").roles("USER").and()
			.withUser("admin").password("pass").roles("ADMIN");
		}

	}
*/
	@RequestMapping("/Home")
	String Home() {
		return "Home";
	}


	/*	@RequestMapping(value = "signup",method = RequestMethod.GET)
	String signup() {
		return "signup";
	}

	@RequestMapping(value = "signup", method = RequestMethod.POST)
	public String signup(@RequestParam String custid, @RequestParam String username,@RequestParam String orgname,@RequestParam String password
			//@RequestParam String role
			){
	    userdata user = new userdata();
	    user.setCustid(custid);
	    user.setUsername(username);
	    user.setOrgname(orgname);
	    user.setPassword(password);
	    //user.setRole(role);
	    UserRepository.save(user);
	    return "Signup";
	}
	 */

	@RequestMapping("/signup")
	String signup() {
		return "signup";
	}



/*
	@RequestMapping("/db")
	String db(Map<String, Object> model) {
		try (Connection connection = dataSource.getConnection()) {
			Statement stmt = connection.createStatement();
			ResultSet rs = stmt.executeQuery("SELECT USERID,CONTENTS FROM botlog ORDER BY NO");

			ArrayList<String> output = new ArrayList<String>();
			while (rs.next()) {
				output.add(rs.getString("USERID") + "　/　" + rs.getString("CONTENTS"));
			}

			model.put("records", output);
			return "db";
		} catch (Exception e) {
			model.put("message", e.getMessage());
			return "error";
		}
	}
*/
	@RequestMapping("/Account")
	String Account() {
		return "Account";
	}
	/*
	String Account(Map<String, Object> model) {
		try (Connection connection = dataSource.getConnection()) {
			Statement stmt = connection.createStatement();
			ResultSet rs = stmt.executeQuery("SELECT no,custid,username,orgname,role FROM userdata ORDER BY NO");

			ArrayList<String> output = new ArrayList<String>();
			while (rs.next()) {
				output.add(rs.getString("custid") + "　|　" + rs.getString("username") + "　|　" + rs.getString("orgname") + "　|　" + rs.getString("role"));
			}

			model.put("records",output);
			return "Account";
		} catch (Exception e) {
			model.put("message", e.getMessage());
			return "error";
		}
	}

	@Bean
	public DataSource dataSource() throws SQLException {
		if (dbUrl == null || dbUrl.isEmpty()) {
			return new HikariDataSource();
		} else {
			HikariConfig config = new HikariConfig();
			config.setJdbcUrl(dbUrl);
			return new HikariDataSource(config);
		}
	}
*/
}