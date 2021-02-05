package com.ideaworks.club.service;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.ideaworks.club.bean.JWTToken;
import com.ideaworks.club.bean.UserBean;
import com.ideaworks.club.util.JWTUtil;

/**
 * 自定义 Realm
 * 
 * @author 王庆港
 * @version 1.0.0
 */
@Component
public class MyRealm extends AuthorizingRealm {
	@Autowired
	private UserService userService;

	@Override
	public boolean supports(AuthenticationToken token) {
		return token instanceof JWTToken;
	}

	@Override
	// 获取授权信息
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		String username = JWTUtil.getUsername(principals.toString());
		UserBean user = userService.getUser(username);
		SimpleAuthorizationInfo simpleAuthorizationInfo = new SimpleAuthorizationInfo();
		simpleAuthorizationInfo.addRole(user.getRole());
		Set<String> permission = new HashSet<>(Arrays.asList(user.getPermission().split(",")));
		simpleAuthorizationInfo.addStringPermissions(permission);
		return simpleAuthorizationInfo;
	}

	@Override
	// 获取认证信息
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken auth) throws AuthenticationException {
		String token = (String) auth.getCredentials();

		String username = JWTUtil.getUsername(token);
		if (username == null) {
			throw new AuthenticationException("token invalid");
		}
		UserBean userBean = userService.getUser(username);
		if (userBean == null) {
			throw new AuthenticationException("User didn't existed!");
		}
		if (!JWTUtil.verify(token, username, userBean.getPassword())) {
			throw new AuthenticationException("Username or password error");
		}
		return new SimpleAuthenticationInfo(token, token, "my_realm");
	}

}
