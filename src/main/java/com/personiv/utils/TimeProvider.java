package com.personiv.utils;

import java.io.Serializable;
import java.util.Date;

import org.springframework.stereotype.Component;


@Component
public class TimeProvider implements Serializable {

	private static final long serialVersionUID = -6919035247507346338L;

	public Date now() {
        return new Date();
    }
}
