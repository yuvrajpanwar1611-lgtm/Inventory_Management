import { createContext, useState } from "react";

export const SupplierContext = createContext();

export const SupplierContextProvider = ({ children }) => {
  const [suppliers, setSuppliers] = useState([]);

  return (
    <SupplierContext.Provider value={[suppliers, setSuppliers]}>
      {children}
    </SupplierContext.Provider>
  );
};