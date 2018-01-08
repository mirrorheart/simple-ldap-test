package com.study.demo1;

import java.util.Hashtable;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.Control;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;

public class LDAPHelper {

	private final String URL = "ldap://47.93.247.42/";
	private final String BASEDN = "ou=People,dc=maxcrc,dc=com";
	private final String FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
	private LdapContext ctx = null;
	private final Control[] connCtls = null;

	private void LDAP_connect() {
		Hashtable<String, String> env = new Hashtable<>();
		env.put(Context.INITIAL_CONTEXT_FACTORY, FACTORY);
		env.put(Context.PROVIDER_URL, URL + BASEDN);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");

		String root = "cn=Manager,dc=maxcrc,dc=com";
		env.put(Context.SECURITY_PRINCIPAL, root);
		env.put(Context.SECURITY_CREDENTIALS, "secret");

		try {
			ctx = new InitialLdapContext(env, connCtls);
			System.out.println("连接成功");
		} catch (AuthenticationException e) {
			System.out.println("连接失败：");
			e.printStackTrace();
		} catch (Exception e) {
			System.out.println("连接出错：");
			e.printStackTrace();
		}
	}
	
	private void closeContext() {
		if(ctx != null) {
			try {
				ctx.close();
			}catch (NamingException e) {
				e.printStackTrace();
			}
		}
	}
	
	private String getUserDN(String uid) {
		String userDN = "";
		LDAP_connect();
		try {
			SearchControls constraints = new SearchControls();
			constraints.setSearchScope(SearchControls.SUBTREE_SCOPE);
			NamingEnumeration<SearchResult> en = ctx.search("", "uid="+uid,constraints);
			if(en == null || !en.hasMoreElements()) {
				System.out.println("未找到该用户");
			}
			while(en!=null&&en.hasMoreElements()) {
				SearchResult si = en.nextElement();
				userDN += si.getName();
				userDN += ","+BASEDN;
			}
		}catch(Exception e) {
			System.out.println("查找用户时产生异常。");
			e.printStackTrace();
		}
		return userDN;
	}
	
	public boolean authenticate(String UID,String password) {
		boolean valide = false;
		String userDN = getUserDN(UID);
		try {
			ctx.addToEnvironment(Context.SECURITY_PRINCIPAL, userDN);
			ctx.addToEnvironment(Context.SECURITY_CREDENTIALS, password);
			ctx.reconnect(connCtls);
			System.out.println(userDN+"验证通过");
			valide = true;
		}catch(NamingException e) {
			System.out.println(userDN + "验证失败");
			e.printStackTrace();
			valide = false;
		}
		closeContext();
		return valide;
	}
	
	public boolean addUser(String usr,String pwd,String uid,String description) {
		try {
			LDAP_connect();
			BasicAttributes attrsbu = new BasicAttributes();
			BasicAttribute objclassSet = new BasicAttribute("objectclass");
			objclassSet.add("inetOrgPerson");
			attrsbu.put(objclassSet);
			attrsbu.put("sn",usr);
			attrsbu.put("cn",usr);
			attrsbu.put("uid",uid);
			attrsbu.put("userPassword",pwd);
			attrsbu.put("description",description);
			ctx.createSubcontext("uid="+uid+"",attrsbu);
			return true;
		}catch(NamingException ex) {
			ex.printStackTrace();
			return false;
		}finally {
			closeContext();
		}
	}
	
	public static void main(String[] args) {
		LDAPHelper ldap = new LDAPHelper();
		ldap.addUser("trick", "secret", "mwx504643", "none");
	}
}
