/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.LinkedList;
import java.util.concurrent.atomic.AtomicInteger;

/**
 *
 * @author secarevi
 */
public class MyThread extends Thread{
    
    private String ip;
    private int min;
    private int max;
    private AtomicInteger ocurrences;
    private int checkedList;
    private LinkedList<Integer> blackListOcurrences;
    private HostBlacklistsDataSourceFacade skds;
    private int BLACK_LIST_ALARM_COUNT;
    
    public MyThread (String ip, int min, int max, AtomicInteger ocurrences, int BLACK_LIST_ALARM_COUNT, HostBlacklistsDataSourceFacade skds) {
        this.ip = ip;
        this.min = min;
        this.max = max;
        this.ocurrences = ocurrences;
        this.BLACK_LIST_ALARM_COUNT = BLACK_LIST_ALARM_COUNT;
        this.skds = skds;
        this.blackListOcurrences = new LinkedList<Integer>();
    }
    
    public void run () {
        int i = min;
        while (i < max && ocurrences.get() < BLACK_LIST_ALARM_COUNT) {
            checkedList++;
            if (skds.isInBlackListServer(i, ip)) {
                blackListOcurrences.add(i);
                ocurrences.getAndIncrement();
            }
            i++;
        }
    }

    public int getCheckedList() {
        return checkedList;
    }

    public LinkedList<Integer> getBlackListOcurrences() {
        return blackListOcurrences;
    }
    
    
}
