package com.codingstudy.login.configuration.auth;

import com.baomidou.mybatisplus.extension.api.R;
import com.codingstudy.login.components.JwtTokenUtil;
import com.codingstudy.login.components.RedisTemplateUtil;
import com.codingstudy.login.components.TokenCache;
import com.codingstudy.login.entity.SysFrontendMenuTable;
import com.codingstudy.login.service.SysFrontendMenuTableService;
import com.codingstudy.login.service.auth.AuthUser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 登录成功操作
 */
@Component
public class MyAuthenticationSuccessHandler extends JSONAuthentication implements AuthenticationSuccessHandler {

    @Autowired
    SysFrontendMenuTableService service;

    /**
     * redis工具类
     */
    @Autowired
    RedisTemplateUtil redisTemplateUtil;

    /**
     * jwt工具类
     */
    @Autowired
    JwtTokenUtil jwtTokenUtil;

    protected Logger log = LoggerFactory.getLogger(this.getClass());

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        System.out.println("-------------------------------进入登录成功执行的操作类--------------------------------------" );
        //取得账号信息
//        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        AuthUser authUser = (AuthUser) authentication.getPrincipal();

        SecurityContextHolder.getContext().setAuthentication(authentication);
        //
        System.out.println("userDetails = " + authUser);
        //取token
        //好的解决方案，登录成功后token存储到数据库中
        //只要token还在过期内，不需要每次重新生成
        //先去缓存中找
        String token = this.token(authUser);

        //加载前端菜单
        List<SysFrontendMenuTable> menus = service.getMenusByUserName(authUser.getUsername());
        //
        Map<String,Object> map = new HashMap<>();
        map.put("username",authUser.getUsername());
        map.put("auth",authUser.getAuthorities());
        map.put("menus",menus);
        map.put("token",token);
        //装入token
        R<Map<String,Object>> data = R.ok(map);
        //输出
        this.WriteJSON(request, response, data);

}

    /**
     * 获取tokne
     */
    String token(AuthUser authUser){
        String redisToken = redisTemplateUtil.getItem(authUser.getUsername());
        String token;
        //如果token不存在就创建一个
        if (redisToken.isEmpty()){
            log.info("初次登录或者token过期");
            // 创建token
            token = jwtTokenUtil.generateToken(authUser);
            redisTemplateUtil.setItemWithExpireTime(authUser.getUsername(),token,jwtTokenUtil.EXPIRATION_TIME);
        }else{
            token = redisToken;
        }
        return token;
    }
}
