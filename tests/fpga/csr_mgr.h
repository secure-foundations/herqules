//
// Copyright (c) 2017, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// Redistributions of source code must retain the above copyright notice, this
// list of conditions and the following disclaimer.
//
// Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// Neither the name of the Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software
// without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.

#ifndef __CSR_MGR_H__
#define __CSR_MGR_H__ 1

#include "opae_svc_wrapper.h"

//
// Manage a standard collection of CSRS.  This is the software-side interface
// to the base cci_csrs RTL module.
//

class CSR_MGR
{
  public:
    CSR_MGR(SVC_WRAPPER& svc) :
        svc(svc)
    {};

    ~CSR_MGR() {};


    //
    // Write/read application-specific CSRs.  The maximum CSR index
    // is application-dependent.
    //
    void writeCSR64(uint64_t idx, uint64_t v)
    {
        svc.write_csr64(idx, v);
    }

    uint64_t readCSR64(uint64_t idx)
    {
        return svc.read_csr64(idx);
    }

    void writeCSR512(uint64_t idx, void *ptr)
    {
        return svc.write_csr512(idx, ptr);
    }


  protected:
    SVC_WRAPPER& svc;
};

#endif // __CSR_MGR_H__
