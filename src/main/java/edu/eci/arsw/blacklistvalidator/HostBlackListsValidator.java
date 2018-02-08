/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator {

    private static final int BLACK_LIST_ALARM_COUNT=5;
    
    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * @param ipaddress suspicious host's IP address.
     * @return  Blacklists numbers where the given host's IP address was found.
     */
    public List<Integer> checkHost(String ipaddress, int partes){
        
        LinkedList<Integer> blackListOcurrences=new LinkedList<>();
        
        AtomicInteger ocurrencesCount = new AtomicInteger(0);
        
        HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();
        
        int checkedListsCount=0;
        
        List<MyThread> threads = new ArrayList<MyThread>();
        
        for (int i = 0 ; i < partes-1 ; i++) {
            MyThread t = new MyThread(ipaddress, ((skds.getRegisteredServersCount()/partes)*i)+1, (skds.getRegisteredServersCount()/partes)*(i+1), ocurrencesCount, BLACK_LIST_ALARM_COUNT, skds);
            threads.add(t);
        }
        
        if (skds.getRegisteredServersCount()%partes == 0) {
            MyThread t = new MyThread(ipaddress, ((skds.getRegisteredServersCount()/partes)*(partes-1))+1, (skds.getRegisteredServersCount()/partes)*partes, ocurrencesCount, BLACK_LIST_ALARM_COUNT, skds);
            threads.add(t);
        } else {
            MyThread t = new MyThread(ipaddress, ((skds.getRegisteredServersCount()/partes)*(partes-1))+1, ((skds.getRegisteredServersCount()/partes)*partes)+(skds.getRegisteredServersCount()%partes), ocurrencesCount, BLACK_LIST_ALARM_COUNT, skds);
            threads.add(t);
        }
        
        for (int i = 0 ; i < threads.size() ; i++) {
            threads.get(i).start();
        }
        
        for (int i = 0 ; i < threads.size() ; i++) {
            try {
                threads.get(i).join();
            } catch (InterruptedException ex) {
                Logger.getLogger(HostBlackListsValidator.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
//        for (int i=0;i<skds.getRegisteredServersCount() && ocurrencesCount<BLACK_LIST_ALARM_COUNT;i++){
//            checkedListsCount++;
//            
//            if (skds.isInBlackListServer(i, ipaddress)){
//                
//                blackListOcurrences.add(i);
//                
//                ocurrencesCount++;
//            }
//        }

        for (int i = 0 ; i < threads.size() ; i++) {
            blackListOcurrences.addAll(threads.get(i).getBlackListOcurrences());
            checkedListsCount = checkedListsCount + threads.get(i).getCheckedList();
        }
        
        if (ocurrencesCount.get()>=BLACK_LIST_ALARM_COUNT){
            skds.reportAsNotTrustworthy(ipaddress);
        }
        else{
            skds.reportAsTrustworthy(ipaddress);
        }                
        
        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{checkedListsCount, skds.getRegisteredServersCount()});
        
        return blackListOcurrences;
    }
    
    
    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());
    
    
    
}
