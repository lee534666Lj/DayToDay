package com.neusoft.daytoday;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * @DO:
 * @Program:pspenv
 * @Author 李君（2765395275）
 * @Create: 2019/3/6 14:38
 *--学海无涯苦作舟--
 */
@SpringBootApplication
@EnableAsync
@EnableAutoConfiguration
@EnableCaching
public class DayToDayApplication {

    public static void main(String[] args) {
        SpringApplication.run(DayToDayApplication.class, args);
    }

}
