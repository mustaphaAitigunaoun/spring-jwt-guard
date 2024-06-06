package org.sid.secservice.constant;

public class JwtUtil {
    public static final String SECRET= "mySecret";
    public static final double JWT_ACCESS_EXPIRE_DATE = 2*60*1000;

    public static final double JWT_REFRESH_EXPIRE_DATE = 5*60*1000;
    public static final String AUTH_HEADER= "Authorization";

    public static final String PREFIX = "Bearer ";

}
