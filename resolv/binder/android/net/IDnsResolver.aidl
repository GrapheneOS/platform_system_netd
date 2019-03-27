/**
 * Copyright (c) 2019, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.net;

import android.net.metrics.INetdEventListener;

/** {@hide} */
interface IDnsResolver {
    /**
     * Returns true if the service is responding.
     */
    boolean isAlive();

   /**
    * Register event listener
    * DnsResolver supports multiple event listeners, but only one per unique address of the
    * binder interface. A newer listener won't be registered if DnsResolver has an old one on
    * the same address of the binder interface.
    *
    * @param listener event listener to register.
    * @throws ServiceSpecificException in case of failure, with an error code corresponding to the
    *         unix errno.
    */
    void registerEventListener(INetdEventListener listener);
}
