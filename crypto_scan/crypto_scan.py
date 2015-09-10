# Based on https://bitbucket.org/daniel_plohmann/simplifire.idascope

from idascope.core.CryptoIdentifier import CryptoIdentifier
from idascope.core.IdaProxy import IdaProxy

ida_proxy = IdaProxy()


def main():
    ida_proxy.Wait()
    
    ci = CryptoIdentifier()

    # Crypto patterns

    ci.scanCryptoPatterns()
    signature_hits = ci.getSignatureHits()    
    
    fdump = open("crypto_sig_scan.txt", "w")
    for signature in signature_hits:        
        fdump.write("%s\n" % signature)
        
        for hit in signature_hits[signature]:
            f_name = ida_proxy.GetFunctionName(hit.start_address)
            f_address = ida_proxy.LocByName(f_name) 
            new_f_name = "crypto_" + f_name
            
            if (f_address != ida_proxy.BAD_ADDR) and (not f_name.startswith("crypto_")):
                ida_proxy.MakeNameEx(f_address, new_f_name, SN_NOWARN)
                fdump.write("0x%x  %s\n" % (f_address, new_f_name))
            else:
                fdump.write("0x%x\n" % hit.start_address)
            
            for xref in hit.code_refs_to:
                xref_name = ida_proxy.GetFunctionName(xref[0])
                xref_address = ida_proxy.LocByName(xref_name) 
                if (xref_address != ida_proxy.BAD_ADDR) and (xref[1] == True) and (not xref_name.startswith("crypto_")):
                    new_x_name = "crypto_ref_" + xref_name
                    ida_proxy.MakeNameEx(xref[0], new_x_name, SN_NOWARN)
                    fdump.write("  0x%x  %s\n" % (xref[0], new_x_name))
        fdump.write("\n")
    fdump.close()

    with open("crypto_patterns_done", "w"):
        pass

    # Custom crypto

    ci.scanAritlog()   
    heur_hits = ci.getAritlogBlocks(0.4, 1.0, 8, 100, 0, 1, True, True, True) 
    
    tmp_dict = {}
    fdump = open("crypto_heur_scan.txt", "w")
    for hit in heur_hits:
        f_name = ida_proxy.GetFunctionName(hit.start_ea)
        f_address = ida_proxy.LocByName(f_name) 
        if f_address not in tmp_dict.keys(): 
            tmp_dict[f_address] = {"function_address": f_address, "num_blocks": 1, \
                                   "num_log_arith_instructions": hit.num_log_arit_instructions}        
            
            if (f_address != ida_proxy.BAD_ADDR) and (not f_name.startswith("crypto_")):
                new_f_name = "crypto_x_" + f_name
                ida_proxy.MakeNameEx(f_address, new_f_name, SN_NOWARN)  
                
            checked_name = ida_proxy.GetFunctionName(f_address)
            fdump.write("0x%x  %s\nnum_arith_instr: %d; arith_rate: %2.2f;\n" % (hit.start_ea, checked_name, \
                            tmp_dict[f_address]["num_log_arith_instructions"], (100.0 * hit.getAritlogRating(True))))
            fdump.write("\n")            
        else:
            tmp_dict[f_address]["num_blocks"] += 1
            tmp_dict[f_address]["num_log_arith_instructions"] += hit.num_log_arit_instructions  
    fdump.close()

    with open("crypto_custom_done", "w"):
        pass

if __name__ == '__main__':
    main()
