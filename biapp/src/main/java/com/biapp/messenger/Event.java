package com.biapp.messenger;

/**
 * Desc: Event. Userd to transfer data among components.
 * <p>
 *
 * @author Linxy
 * @date 2017/3/7
 */

public class Event {

    private int tag;

    public Event(int tag) {
        this.tag = tag;
    }

    public int getTag() {
        return tag;
    }
}
